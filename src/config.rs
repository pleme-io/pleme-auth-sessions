use std::time::Duration;

/// Session service configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Redis key prefix for sessions (default: "session:")
    pub key_prefix: String,

    /// Session expiration duration (default: 24 hours)
    pub session_duration: Duration,

    /// Refresh token tracking key prefix (default: "refresh:")
    pub refresh_token_prefix: String,

    /// Refresh token expiration duration (default: 7 days)
    pub refresh_token_duration: Duration,

    /// Maximum active sessions per user (default: 5)
    /// When exceeded, oldest sessions are automatically invalidated
    pub max_sessions_per_user: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            key_prefix: "session:".to_string(),
            session_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            refresh_token_prefix: "refresh:".to_string(),
            refresh_token_duration: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            max_sessions_per_user: 5,
        }
    }
}
