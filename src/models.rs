use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session model stored in Redis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID (used as Redis key)
    pub id: Uuid,

    /// User ID who owns this session
    pub user_id: Uuid,

    /// Session data (access token, refresh token, metadata)
    pub data: SessionData,

    /// When the session was created
    pub created_at: DateTime<Utc>,

    /// When the session expires
    pub expires_at: DateTime<Utc>,

    /// Last activity timestamp (for idle timeout tracking)
    pub last_activity: DateTime<Utc>,

    /// IP address of the client that created this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,

    /// User agent of the client that created this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl Session {
    /// Create a new session
    pub fn new(
        user_id: Uuid,
        data: SessionData,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            data,
            created_at: now,
            expires_at,
            last_activity: now,
            client_ip: None,
            user_agent: None,
        }
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Add client metadata
    pub fn with_client_info(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.client_ip = ip;
        self.user_agent = user_agent;
        self
    }
}

/// Session data containing tokens and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Access token JWT
    pub access_token: String,

    /// Refresh token JWT
    pub refresh_token: String,

    /// User email (cached for convenience)
    pub user_email: String,

    /// Custom metadata (extensible for application-specific data)
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl SessionData {
    /// Create new session data
    pub fn new(
        access_token: String,
        refresh_token: String,
        user_email: String,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            user_email,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Add metadata to session
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}
