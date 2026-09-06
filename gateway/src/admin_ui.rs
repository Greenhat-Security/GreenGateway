//! admin ui boundary extracted from the application composition root.
use super::*;

pub(super) async fn admin_ui_index(State(state): State<AppState>) -> Response {
    record_request(ADMIN_UI_ROUTE);
    admin_ui_index_response(
        &state.routes.admin,
        &state.csrf_cookie_name,
        &state.csrf_header_name,
    )
}

pub(super) async fn admin_ui_asset(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Response {
    record_request(ADMIN_UI_ROUTE);

    let asset_path = path.trim_start_matches('/');
    if !asset_path.is_empty() {
        if let Some(asset) = AdminUiAssets::get(asset_path) {
            return embedded_asset_response(asset_path, asset);
        }
    }

    admin_ui_index_response(
        &state.routes.admin,
        &state.csrf_cookie_name,
        &state.csrf_header_name,
    )
}

pub(super) fn admin_ui_index_response(
    routes: &AdminRoutes,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
) -> Response {
    match AdminUiAssets::get(ADMIN_UI_INDEX) {
        Some(asset) => admin_ui_html_response(routes, csrf_cookie_name, csrf_header_name, asset),
        None => internal_server_error("admin UI index not embedded"),
    }
}

pub(super) fn admin_ui_html_response(
    routes: &AdminRoutes,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
    asset: rust_embed::EmbeddedFile,
) -> Response {
    let html = match std::str::from_utf8(asset.data.as_ref()) {
        Ok(html) => rewrite_admin_ui_index(html, routes, csrf_cookie_name, csrf_header_name),
        Err(err) => {
            tracing::error!(error = %err, "embedded admin UI index is not UTF-8");
            return internal_server_error("admin UI index is not valid UTF-8");
        }
    };

    (
        [
            (header::CONTENT_TYPE, content_type_for_path(ADMIN_UI_INDEX)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(ADMIN_UI_CONTENT_SECURITY_POLICY),
            ),
        ],
        html,
    )
        .into_response()
}

pub(super) fn rewrite_admin_ui_index(
    html: &str,
    routes: &AdminRoutes,
    csrf_cookie_name: &str,
    csrf_header_name: &str,
) -> String {
    let admin_base_with_slash = format!("{}/", routes.ui_prefix);
    let html = html.replace("/admin/", &admin_base_with_slash);
    let config_meta = format!(
        r#"    <meta name="greengateway-admin-base" content="{}" />
    <meta name="greengateway-admin-api-base" content="{}" />
    <meta name="greengateway-csrf-cookie-name" content="{}" />
    <meta name="greengateway-csrf-header-name" content="{}" />
"#,
        html_attribute_value(&routes.ui_prefix),
        html_attribute_value(&routes.api_prefix),
        html_attribute_value(csrf_cookie_name),
        html_attribute_value(csrf_header_name),
    );

    html.replacen("  </head>", &format!("{config_meta}  </head>"), 1)
}

pub(super) fn html_attribute_value(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(super) fn embedded_asset_response(path: &str, asset: rust_embed::EmbeddedFile) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type_for_path(path)),
            (
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(ADMIN_UI_CONTENT_SECURITY_POLICY),
            ),
        ],
        asset.data.into_owned(),
    )
        .into_response()
}

pub(super) fn content_type_for_path(path: &str) -> HeaderValue {
    HeaderValue::from_str(mime_guess::from_path(path).first_or_octet_stream().as_ref())
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
}
