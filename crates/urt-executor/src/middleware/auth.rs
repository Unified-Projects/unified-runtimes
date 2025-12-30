//! Authentication middleware

use crate::error::ExecutorError;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use subtle::ConstantTimeEq;

/// Constant-time string comparison to prevent timing attacks
/// Returns true if strings are equal, false otherwise
#[inline]
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    // Length check must be done first, but this is acceptable
    // as token length is typically fixed or public knowledge
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(auth_header: Option<&str>) -> Option<&str> {
    auth_header
        .filter(|h| h.starts_with("Bearer "))
        .map(|h| h.trim_start_matches("Bearer ").trim())
}

/// Authentication middleware
/// Validates Bearer token against executor secret
pub async fn auth_middleware(
    State(secret): State<String>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // If no secret configured, skip auth
    if secret.is_empty() {
        return Ok(next.run(request).await);
    }

    // Extract bearer token
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    let token = extract_bearer_token(auth_header);

    match token {
        Some(t) if constant_time_compare(t, &secret) => Ok(next.run(request).await),
        _ => Err(ExecutorError::Unauthorized.into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(
            extract_bearer_token(Some("Bearer  spaced  ")),
            Some("spaced")
        );
        assert_eq!(extract_bearer_token(Some("Basic abc")), None);
        assert_eq!(extract_bearer_token(None), None);
    }

    #[test]
    fn test_constant_time_compare() {
        // Equal strings should return true
        assert!(constant_time_compare("secret", "secret"));
        assert!(constant_time_compare("", ""));
        assert!(constant_time_compare("a", "a"));

        // Different strings should return false
        assert!(!constant_time_compare("secret", "Secret"));
        assert!(!constant_time_compare("secret", "secre"));
        assert!(!constant_time_compare("short", "longer_string"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("a", "b"));
    }
}
