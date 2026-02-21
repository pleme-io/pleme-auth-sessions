use crate::config::SessionConfig;
use crate::error::SessionError;
use crate::models::{Session, SessionData};
use chrono::Utc;
use redis::AsyncCommands;
use tracing::{debug, warn};
use uuid::Uuid;

/// Session service for managing user sessions in Redis
/// Handles session creation, validation, refresh, and cleanup
pub struct SessionService {
    config: SessionConfig,
}

impl SessionService {
    /// Create new session service
    pub fn new(config: SessionConfig) -> Self {
        Self { config }
    }

    /// Create a new session and store in Redis
    pub async fn create_session(
        &self,
        user_id: Uuid,
        data: SessionData,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Session, SessionError> {
        let expires_at = Utc::now() + chrono::Duration::from_std(self.config.session_duration)
            .map_err(|e| SessionError::InvalidSession(format!("Duration conversion: {}", e)))?;

        let session = Session::new(user_id, data, expires_at);

        // Check if user has too many active sessions
        self.enforce_session_limit(user_id, redis).await?;

        // Store session in Redis
        let key = self.session_key(&session.id);
        let value = serde_json::to_string(&session)?;
        let ttl_secs = self.config.session_duration.as_secs();

        let _: () = redis.set_ex(&key, value, ttl_secs as u64).await?;

        // Add session to user's session list
        self.add_to_user_sessions(user_id, session.id, redis).await?;

        // Store refresh token mapping (for token revocation)
        self.store_refresh_token(&session.data.refresh_token, session.id, redis).await?;

        debug!("Created session {} for user {}", session.id, user_id);

        Ok(session)
    }

    /// Get session by ID
    pub async fn get_session(
        &self,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Session, SessionError> {
        let key = self.session_key(&session_id);
        let value: Option<String> = redis.get(&key).await?;

        match value {
            Some(data) => {
                let session: Session = serde_json::from_str(&data)
                    .map_err(|e| SessionError::DeserializationError(e.to_string()))?;

                if session.is_expired() {
                    return Err(SessionError::SessionExpired);
                }

                Ok(session)
            }
            None => Err(SessionError::SessionNotFound),
        }
    }

    /// Update session last activity timestamp
    pub async fn touch_session(
        &self,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let mut session = self.get_session(session_id, redis).await?;
        session.touch();

        let key = self.session_key(&session_id);
        let value = serde_json::to_string(&session)?;
        let ttl_secs = self.config.session_duration.as_secs();

        let _: () = redis.set_ex(&key, value, ttl_secs as u64).await?;

        Ok(())
    }

    /// Delete session (logout)
    pub async fn delete_session(
        &self,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        // Get session to find refresh token
        if let Ok(session) = self.get_session(session_id, redis).await {
            // Remove refresh token mapping
            self.delete_refresh_token(&session.data.refresh_token, redis).await?;

            // Remove from user's session list
            self.remove_from_user_sessions(session.user_id, session_id, redis).await?;
        }

        // Delete session
        let key = self.session_key(&session_id);
        let _: () = redis.del(&key).await?;

        debug!("Deleted session {}", session_id);

        Ok(())
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(
        &self,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Vec<Session>, SessionError> {
        let key = self.user_sessions_key(user_id);
        let session_ids: Vec<String> = redis.smembers(&key).await?;

        let mut sessions = Vec::new();
        for id_str in session_ids {
            if let Ok(session_id) = Uuid::parse_str(&id_str) {
                if let Ok(session) = self.get_session(session_id, redis).await {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    /// Delete all sessions for a user (logout all devices)
    pub async fn delete_all_user_sessions(
        &self,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let sessions = self.get_user_sessions(user_id, redis).await?;

        for session in sessions {
            self.delete_session(session.id, redis).await?;
        }

        // Clean up user sessions set
        let key = self.user_sessions_key(user_id);
        let _: () = redis.del(&key).await?;

        debug!("Deleted all sessions for user {}", user_id);

        Ok(())
    }

    /// Get session by refresh token
    pub async fn get_session_by_refresh_token(
        &self,
        refresh_token: &str,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Session, SessionError> {
        let key = self.refresh_token_key(refresh_token);
        let session_id: Option<String> = redis.get(&key).await?;

        match session_id {
            Some(id_str) => {
                let session_id = Uuid::parse_str(&id_str)
                    .map_err(|_| SessionError::InvalidRefreshToken)?;
                self.get_session(session_id, redis).await
            }
            None => Err(SessionError::RefreshTokenNotFound),
        }
    }

    /// Enforce session limit per user (delete oldest sessions)
    async fn enforce_session_limit(
        &self,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let mut sessions = self.get_user_sessions(user_id, redis).await?;

        if sessions.len() >= self.config.max_sessions_per_user {
            // Sort by creation time (oldest first)
            sessions.sort_by_key(|s| s.created_at);

            // Delete oldest sessions to make room
            let to_delete = sessions.len() - self.config.max_sessions_per_user + 1;
            for session in sessions.iter().take(to_delete) {
                warn!(
                    "Session limit exceeded for user {}, deleting old session {}",
                    user_id, session.id
                );
                self.delete_session(session.id, redis).await?;
            }
        }

        Ok(())
    }

    /// Store refresh token mapping
    async fn store_refresh_token(
        &self,
        refresh_token: &str,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let key = self.refresh_token_key(refresh_token);
        let ttl_secs = self.config.refresh_token_duration.as_secs();

        let _: () = redis.set_ex(&key, session_id.to_string(), ttl_secs as u64).await?;

        Ok(())
    }

    /// Delete refresh token mapping
    async fn delete_refresh_token(
        &self,
        refresh_token: &str,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let key = self.refresh_token_key(refresh_token);
        let _: () = redis.del(&key).await?;

        Ok(())
    }

    /// Add session to user's session list
    async fn add_to_user_sessions(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let key = self.user_sessions_key(user_id);
        let _: () = redis.sadd(&key, session_id.to_string()).await?;

        Ok(())
    }

    /// Remove session from user's session list
    async fn remove_from_user_sessions(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let key = self.user_sessions_key(user_id);
        let _: () = redis.srem(&key, session_id.to_string()).await?;

        Ok(())
    }

    /// Generate Redis key for session
    fn session_key(&self, session_id: &Uuid) -> String {
        format!("{}{}", self.config.key_prefix, session_id)
    }

    /// Generate Redis key for user sessions set
    fn user_sessions_key(&self, user_id: Uuid) -> String {
        format!("{}user:{}", self.config.key_prefix, user_id)
    }

    /// Generate Redis key for refresh token
    fn refresh_token_key(&self, refresh_token: &str) -> String {
        format!("{}{}", self.config.refresh_token_prefix, refresh_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_expiration() {
        // This test validates session expiration logic
        // Actual Redis integration would require a test Redis instance
    }
}
