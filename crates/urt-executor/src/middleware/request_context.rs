//! Request context middleware for correlation IDs and structured access logging.

use axum::{
    extract::Request,
    http::{header, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{debug, warn, Level};
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_REQUEST_ID_LEN: usize = 128;

fn sanitize_request_id(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_REQUEST_ID_LEN {
        return None;
    }

    let valid = trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));

    if valid {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Adds/propagates `x-request-id` and emits structured request completion logs.
pub async fn request_context_middleware(mut request: Request, next: Next) -> Response {
    let capture_debug_context = tracing::enabled!(Level::DEBUG);
    let debug_method = capture_debug_context.then(|| request.method().clone());
    let debug_path = capture_debug_context.then(|| {
        request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| request.uri().path().to_string())
    });

    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_request_id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), header_value);
    }

    let start = Instant::now();
    let mut response = next.run(request).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();

    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), header_value);
    }
    response
        .headers_mut()
        .entry(header::SERVER)
        .or_insert(HeaderValue::from_static("Executor"));

    if status >= 500 {
        if let (Some(method), Some(path)) = (debug_method.as_ref(), debug_path.as_ref()) {
            warn!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status,
                duration_ms,
                "http_request_failed"
            );
        } else {
            warn!(
                request_id = %request_id,
                status,
                duration_ms,
                "http_request_failed"
            );
        }
    } else if let (Some(method), Some(path)) = (debug_method.as_ref(), debug_path.as_ref()) {
        debug!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status,
            duration_ms,
            "http_request"
        );
    }

    response
}
