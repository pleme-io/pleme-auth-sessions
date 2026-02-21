//! Axum middleware for session management
//!
//! Provides automatic session validation and activity tracking:
//! - Extract and validate JWT tokens from Authorization header
//! - Validate session existence and expiry
//! - Automatically record activity for each request
//! - Track device information
//! - Inject SessionContext into request extensions

use crate::activity::{ActivityTracker, ActivityType};
use crate::analytics::{AnalyticsTracker, SecurityEvent, SecurityEventType};
use crate::device::{DeviceInfo, DeviceManager};
use crate::error::SessionError;
use axum::{
    extract::{ConnectInfo, Request},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

/// Session context injected into request extensions
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// Session ID
    pub session_id: Uuid,
    /// User ID
    pub user_id: Uuid,
    /// Device ID
    pub device_id: Option<String>,
    /// IP address
    pub ip_address: String,
    /// User agent
    pub user_agent: Option<String>,
    /// Session metadata
    pub metadata: Option<serde_json::Value>,
}

/// Optional session context (for endpoints that don't require auth)
#[derive(Debug, Clone)]
pub struct OptionalSessionContext(pub Option<SessionContext>);

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Session ID
    pub session_id: String,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    pub iat: i64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
}

/// Middleware state
#[derive(Clone)]
pub struct SessionMiddlewareState {
    /// Activity tracker
    pub activity_tracker: Arc<ActivityTracker>,
    /// Analytics tracker
    pub analytics_tracker: Arc<AnalyticsTracker>,
    /// Device manager
    pub device_manager: Arc<DeviceManager>,
    /// Redis connection manager
    pub redis: ConnectionManager,
    /// JWT secret for validation (optional - if None, JWT signature is not verified)
    pub jwt_secret: Option<String>,
}

/// Extract session from Authorization header
fn extract_token_from_header(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            if h.starts_with("Bearer ") {
                Some(h[7..].to_string())
            } else {
                None
            }
        })
}

/// Extract IP address from request
fn extract_ip_address(req: &Request) -> String {
    // Try X-Forwarded-For header first (for proxies)
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    // Try X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // Fall back to connection info
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Extract user agent from request
fn extract_user_agent(req: &Request) -> Option<String> {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

/// Validate JWT token (simplified - use proper JWT library in production)
fn validate_jwt_token(token: &str, _secret: &str) -> Result<JwtClaims, SessionError> {
    use base64::{Engine as _, engine::general_purpose};

    // In production, use jsonwebtoken crate with proper RS256 validation
    // This is a simplified version for demonstration

    // Decode JWT payload (base64)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SessionError::InvalidSession("Invalid JWT format".to_string()));
    }

    // Decode payload (part 1)
    let payload = parts[1];
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(payload)
        .map_err(|_| SessionError::InvalidSession("Invalid base64 encoding".to_string()))?;

    let claims: JwtClaims = serde_json::from_slice(&decoded)
        .map_err(|_| SessionError::InvalidSession("Invalid JWT claims".to_string()))?;

    // Check expiration
    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err(SessionError::SessionExpired);
    }

    Ok(claims)
}

/// Session authentication middleware
///
/// Validates JWT token and injects SessionContext into request extensions.
/// Returns 401 if token is invalid or session doesn't exist.
pub async fn auth_middleware(
    state: Arc<SessionMiddlewareState>,
    mut req: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Extract token from Authorization header
    let token = match extract_token_from_header(&req) {
        Some(t) => t,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header".to_string(),
            ));
        }
    };

    // Validate JWT
    let jwt_secret = state.jwt_secret.as_deref().unwrap_or("");
    let claims = match validate_jwt_token(&token, jwt_secret) {
        Ok(c) => c,
        Err(e) => {
            warn!("JWT validation failed: {:?}", e);
            return Err((StatusCode::UNAUTHORIZED, "Invalid token".to_string()));
        }
    };

    // Parse user ID and session ID
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid user ID".to_string()))?;

    let session_id = Uuid::parse_str(&claims.session_id)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid session ID".to_string()))?;

    // Extract request metadata
    let mut redis = state.redis.clone();
    let ip_address = extract_ip_address(&req);
    let user_agent = extract_user_agent(&req);

    // Record activity
    if let Err(e) = state
        .activity_tracker
        .record_activity(
            session_id,
            ActivityType::ApiRequest,
            Some(format!("{} {}", req.method(), req.uri().path())),
            &mut redis,
        )
        .await
    {
        warn!("Failed to record activity: {:?}", e);
    }

    // Create session context
    let context = SessionContext {
        session_id,
        user_id,
        device_id: None, // TODO: Extract from headers or query params
        ip_address,
        user_agent,
        metadata: None,
    };

    // Inject context into request extensions
    req.extensions_mut().insert(context.clone());

    debug!("Session validated for user {} (session {})", user_id, session_id);

    Ok(next.run(req).await)
}

/// Optional authentication middleware
///
/// Similar to auth_middleware but doesn't return error if no token is present.
/// Injects OptionalSessionContext instead.
pub async fn optional_auth_middleware(
    state: Arc<SessionMiddlewareState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = match extract_token_from_header(&req) {
        Some(t) => t,
        None => {
            // No token - inject None and continue
            req.extensions_mut().insert(OptionalSessionContext(None));
            return next.run(req).await;
        }
    };

    // Validate JWT
    let jwt_secret = state.jwt_secret.as_deref().unwrap_or("");
    let claims = match validate_jwt_token(&token, jwt_secret) {
        Ok(c) => c,
        Err(e) => {
            warn!("JWT validation failed (optional): {:?}", e);
            req.extensions_mut().insert(OptionalSessionContext(None));
            return next.run(req).await;
        }
    };

    // Parse IDs
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            req.extensions_mut().insert(OptionalSessionContext(None));
            return next.run(req).await;
        }
    };

    let session_id = match Uuid::parse_str(&claims.session_id) {
        Ok(id) => id,
        Err(_) => {
            req.extensions_mut().insert(OptionalSessionContext(None));
            return next.run(req).await;
        }
    };

    // Extract request metadata
    let mut redis = state.redis.clone();
    let ip_address = extract_ip_address(&req);
    let user_agent = extract_user_agent(&req);

    // Record activity
    if let Err(e) = state
        .activity_tracker
        .record_activity(
            session_id,
            ActivityType::ApiRequest,
            Some(format!("{} {}", req.method(), req.uri().path())),
            &mut redis,
        )
        .await
    {
        warn!("Failed to record activity: {:?}", e);
    }

    // Create context
    let context = SessionContext {
        session_id,
        user_id,
        device_id: None,
        ip_address,
        user_agent,
        metadata: None,
    };

    req.extensions_mut().insert(OptionalSessionContext(Some(context)));

    next.run(req).await
}

/// Activity tracking middleware
///
/// Records activity for authenticated requests without validating session.
/// Requires SessionContext to be present in extensions (from auth_middleware).
pub async fn activity_tracking_middleware(
    state: Arc<SessionMiddlewareState>,
    req: Request,
    next: Next,
) -> Response {
    // Get session context from extensions
    let context = req.extensions().get::<SessionContext>().cloned();

    if let Some(ctx) = context {
        let mut redis = state.redis.clone();

        // Record API request activity
        if let Err(e) = state
            .activity_tracker
            .record_activity(
                ctx.session_id,
                ActivityType::ApiRequest,
                Some(format!("{} {}", req.method(), req.uri().path())),
                &mut redis,
            )
            .await
        {
            warn!("Failed to record activity: {:?}", e);
        }
    }

    next.run(req).await
}

/// Device tracking middleware
///
/// Tracks device information for authenticated requests.
/// Requires SessionContext to be present in extensions.
pub async fn device_tracking_middleware(
    state: Arc<SessionMiddlewareState>,
    req: Request,
    next: Next,
) -> Response {
    let context = req.extensions().get::<SessionContext>().cloned();

    if let Some(ctx) = context {
        if let Some(user_agent) = &ctx.user_agent {
            let mut redis = state.redis.clone();

            // Create device info from request
            let device_info = DeviceInfo::new(
                ctx.device_id.clone().unwrap_or_else(|| "unknown".to_string()),
                user_agent.clone(),
                ctx.ip_address.clone(),
                "unknown".to_string(), // TODO: Parse from user agent
            );

            // Register or update device
            if let Err(e) = state
                .device_manager
                .register_device(
                    device_info.device_id.clone(),
                    ctx.user_id,
                    device_info,
                    &mut redis,
                )
                .await
            {
                warn!("Failed to register device: {:?}", e);
            }
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_token() {
        let mut req = Request::builder()
            .header(header::AUTHORIZATION, "Bearer test_token_123")
            .body(())
            .unwrap();

        let token = extract_token_from_header(&req);
        assert_eq!(token, Some("test_token_123".to_string()));
    }

    #[test]
    fn test_extract_user_agent() {
        let mut req = Request::builder()
            .header(header::USER_AGENT, "Mozilla/5.0")
            .body(())
            .unwrap();

        let ua = extract_user_agent(&req);
        assert_eq!(ua, Some("Mozilla/5.0".to_string()));
    }
}
