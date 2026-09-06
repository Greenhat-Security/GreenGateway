// The async tool pipeline needs this solver depth on the pinned coverage compiler.
#![recursion_limit = "256"]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    convert::Infallible,
    fs,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Path, Query, Request as AxumRequest, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{any, get, patch, post, put},
    Extension, Json, Router,
};
use bytes::Bytes;
use futures_util::{stream, Stream};
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::net::SocketAddr;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    prelude::*,
};
#[cfg(test)]
use url::Url;
use zeroize::{Zeroize, Zeroizing};

mod app_state;
#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
use app_state::*;
mod api_contracts;
use api_contracts::*;
mod bootstrap;
use bootstrap::*;
mod routing;
use routing::*;
mod probes;
use probes::*;
mod admin_identity;
use admin_identity::*;
mod admin_connections;
use admin_connections::*;
mod admin_policy;
use admin_policy::*;
mod admin_tokens;
use admin_tokens::*;
mod admin_tools;
use admin_tools::*;
mod admin_observability;
use admin_observability::*;
mod admin_ui;
use admin_ui::*;
mod admin_authorization;
use admin_authorization::*;
mod admin_events;
use admin_events::*;
mod admin_responses;
use admin_responses::*;

mod audit;
mod auth;
mod client_ip;
#[cfg(feature = "postgres")]
mod cluster_maintenance;
#[cfg(feature = "postgres")]
mod cluster_membership;
mod cluster_status;
mod config;
mod connection_secret_maintenance;
mod connections;
mod discovery;
mod egress;
mod ha;
mod ha_status;
/// The one-way standalone-to-cluster import (issue #241, PR 15). Only a
/// `postgres` build has a cluster to import into; a feature-off build
/// refuses the subcommand in `run` with a clear message.
#[cfg(feature = "postgres")]
mod import;
mod inbound_tls;
mod lifecycle;
mod mcp;
mod metrics;
mod middleware;
mod path_match;
mod proxy;
mod rbac;
#[cfg(feature = "postgres")]
mod security_cluster;
mod storage;
mod tools;
mod upstream_route;

#[cfg(test)]
use lifecycle::serve_router;
use lifecycle::{
    serve_gateway, GatewayApp, GatewayApps, GatewayLifecycle, GrpcApp, ShutdownConfig,
};
use proxy::{ProxyClassifier, ProxyState};
#[cfg(all(test, feature = "postgres"))]
use storage::AuditEventStore as _;
#[cfg(feature = "postgres")]
use storage::PolicyControlPlane as _;
use storage::PrincipalDirectoryStore;
#[cfg(feature = "postgres")]
use storage::ToolControlPlane;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Rust's Termination impl prints the Debug form, which for a
            // startup failure is a struct dump rather than the sentence the
            // error type carefully builds. Startup errors are frequently an
            // operator's only diagnostic -- the admin API is not up yet -- so
            // print Display, and the source chain behind it.
            eprintln!("Error: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            std::process::ExitCode::FAILURE
        }
    }
}
