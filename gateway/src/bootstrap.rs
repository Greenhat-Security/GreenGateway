//! Process startup, the composition root `main` hands control to.
//!
//! [`run`] runs the one-shot command the arguments name (`commands.rs`)
//! or starts serving with [`start_serving`] (`stages.rs`): the
//! configuration compiler, then preflight, whose cluster-mode half reads
//! the authority (`cluster_preflight.rs`), activation, which builds the
//! gateway (`gateway_app.rs`) with its authentication and admin login
//! (`identity.rs`) and its tool bindings (`tool_bindings.rs`), and
//! serving. Each module's items keep the visibility they had here.
use super::*;

mod commands;
pub(super) use commands::*;
mod stages;
pub(super) use stages::*;
#[cfg(feature = "postgres")]
mod cluster_preflight;
#[cfg(feature = "postgres")]
pub(super) use cluster_preflight::*;
mod gateway_app;
pub(super) use gateway_app::*;
mod identity;
pub(super) use identity::*;
mod tool_bindings;
pub(super) use tool_bindings::*;

pub(super) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if run_one_shot_command().await? {
        return Ok(());
    }

    let process_started_at = Instant::now();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(false),
        )
        .with(production_tracing_filter())
        .init();

    // Serving startup runs in stages (`start_serving`): the configuration
    // compiler, then preflight, activation and serving. A configuration the
    // compiler refuses is printed as it reports it, before any stage runs;
    // a stage's failure goes back to `main` like every other startup error.
    let mut stages = ProcessStartup { process_started_at };
    match start_serving(&mut stages, config::process_environment).await {
        Ok(()) => Ok(()),
        Err(StartupFailure::Configuration(err)) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
        Err(StartupFailure::Bundle(diagnostics)) => {
            for diagnostic in diagnostics {
                eprintln!("{diagnostic}");
            }
            std::process::exit(1);
        }
        Err(StartupFailure::Stage(error)) => Err(error),
    }
}

pub(super) fn production_tracing_filter() -> Targets {
    // rmcp emits peer metadata, raw transport errors, and session identifiers from its
    // internal tracing calls. Keep the dependency disabled globally; GreenGateway emits its own
    // bounded MCP outcome categories at the integration boundary.
    Targets::new()
        .with_default(LevelFilter::INFO)
        .with_target("rmcp", LevelFilter::OFF)
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
