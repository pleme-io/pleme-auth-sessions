//! Session analytics and metrics
//!
//! Tracks session-related metrics and security events:
//! - Session duration statistics
//! - Activity pattern analysis
//! - Security event tracking
//! - Geographic distribution
//! - Device usage patterns

use crate::error::SessionError;
use chrono::{DateTime, Duration, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    /// Failed login attempt
    FailedLogin,
    /// Successful login
    SuccessfulLogin,
    /// Session created
    SessionCreated,
    /// Session expired
    SessionExpired,
    /// Session terminated by user
    SessionTerminated,
    /// Token refresh
    TokenRefresh,
    /// Failed token refresh
    FailedTokenRefresh,
    /// Login from new device
    NewDevice,
    /// Login from new location
    NewLocation,
    /// Suspicious activity detected
    SuspiciousActivity,
    /// Account locked
    AccountLocked,
    /// Account unlocked
    AccountUnlocked,
    /// Password changed
    PasswordChanged,
    /// Email changed
    EmailChanged,
    /// Two-factor authentication enabled
    TwoFactorEnabled,
    /// Two-factor authentication disabled
    TwoFactorDisabled,
}

/// Security event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: SecurityEventType,
    /// User ID
    pub user_id: Uuid,
    /// Session ID (if applicable)
    pub session_id: Option<Uuid>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Device ID
    pub device_id: Option<String>,
    /// Geographic location (city, country)
    pub location: Option<String>,
    /// Additional metadata
    pub metadata: Option<HashMap<String, String>>,
}

impl SecurityEvent {
    /// Create new security event
    pub fn new(event_type: SecurityEventType, user_id: Uuid) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            user_id,
            session_id: None,
            ip_address: None,
            user_agent: None,
            device_id: None,
            location: None,
            metadata: None,
        }
    }

    /// Builder pattern for setting fields
    pub fn with_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, ua: String) -> Self {
        self.user_agent = Some(ua);
        self
    }

    pub fn with_device(mut self, device_id: String) -> Self {
        self.device_id = Some(device_id);
        self
    }

    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Session duration statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDurationStats {
    /// Average session duration in seconds
    pub avg_duration_secs: f64,
    /// Minimum session duration in seconds
    pub min_duration_secs: u64,
    /// Maximum session duration in seconds
    pub max_duration_secs: u64,
    /// Median session duration in seconds
    pub median_duration_secs: u64,
    /// Total number of sessions
    pub total_sessions: usize,
}

/// Activity pattern statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityPatternStats {
    /// Peak activity hours (0-23)
    pub peak_hours: Vec<u32>,
    /// Activity count by hour
    pub activity_by_hour: HashMap<u32, usize>,
    /// Most common activity types
    pub top_activities: Vec<(String, usize)>,
    /// Average activities per session
    pub avg_activities_per_session: f64,
}

/// Device usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceUsageStats {
    /// Total unique devices
    pub total_devices: usize,
    /// Trusted devices count
    pub trusted_devices: usize,
    /// Untrusted devices count
    pub untrusted_devices: usize,
    /// Device types distribution (mobile, desktop, tablet)
    pub device_types: HashMap<String, usize>,
    /// Browser distribution
    pub browsers: HashMap<String, usize>,
    /// Operating system distribution
    pub operating_systems: HashMap<String, usize>,
}

/// Geographic distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicStats {
    /// Sessions by country
    pub sessions_by_country: HashMap<String, usize>,
    /// Sessions by city
    pub sessions_by_city: HashMap<String, usize>,
    /// Unique locations count
    pub unique_locations: usize,
}

/// Comprehensive analytics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsSummary {
    /// Time period for this summary
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,

    /// Session statistics
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub expired_sessions: usize,

    /// Duration statistics
    pub duration_stats: SessionDurationStats,

    /// Activity patterns
    pub activity_patterns: ActivityPatternStats,

    /// Security events count
    pub security_events: HashMap<SecurityEventType, usize>,

    /// Device usage
    pub device_usage: DeviceUsageStats,

    /// Geographic distribution
    pub geographic_stats: GeographicStats,
}

/// Analytics tracker
pub struct AnalyticsTracker {
    /// Retention period for events (default: 90 days)
    retention_days: i64,
}

impl AnalyticsTracker {
    /// Create new analytics tracker
    pub fn new(retention_days: i64) -> Self {
        Self { retention_days }
    }

    /// Create with default retention (90 days)
    pub fn default() -> Self {
        Self::new(90)
    }

    /// Record security event
    pub async fn record_security_event(
        &self,
        event: SecurityEvent,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        // Store event in user's security event log
        let key = format!("user:{}:security_events", event.user_id);
        let score = event.timestamp.timestamp();
        let value = serde_json::to_string(&event)?;

        let _: () = redis.zadd(&key, value, score).await?;

        // Set expiration
        let retention_secs = self.retention_days * 24 * 60 * 60;
        let _: () = redis.expire(&key, retention_secs).await?;

        // Clean up old events
        let cutoff = (Utc::now() - Duration::days(self.retention_days)).timestamp();
        let _: () = redis.zrembyscore(&key, "-inf", cutoff).await?;

        // Increment global event counter
        let counter_key = format!("analytics:security_events:{}", event.event_type.to_string());
        let _: () = redis.incr(&counter_key, 1).await?;
        let _: () = redis.expire(&counter_key, retention_secs).await?;

        match event.event_type {
            SecurityEventType::FailedLogin => {
                warn!("Failed login for user {}", event.user_id);
            }
            SecurityEventType::SuspiciousActivity => {
                warn!("Suspicious activity for user {}: {:?}", event.user_id, event.metadata);
            }
            SecurityEventType::AccountLocked => {
                warn!("Account locked for user {}", event.user_id);
            }
            _ => {
                debug!("Security event: {:?} for user {}", event.event_type, event.user_id);
            }
        }

        Ok(())
    }

    /// Get security events for user
    pub async fn get_user_security_events(
        &self,
        user_id: Uuid,
        limit: usize,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Vec<SecurityEvent>, SessionError> {
        let key = format!("user:{}:security_events", user_id);

        // Get recent events (most recent first)
        let results: Vec<String> = redis
            .zrevrange(&key, 0, (limit - 1) as isize)
            .await
            .unwrap_or_default();

        let mut events = Vec::new();
        for result in results {
            if let Ok(event) = serde_json::from_str::<SecurityEvent>(&result) {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Get security events for time range
    pub async fn get_security_events_range(
        &self,
        user_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Vec<SecurityEvent>, SessionError> {
        let key = format!("user:{}:security_events", user_id);

        let start_score = start.timestamp();
        let end_score = end.timestamp();

        let results: Vec<String> = redis
            .zrangebyscore(&key, start_score, end_score)
            .await
            .unwrap_or_default();

        let mut events = Vec::new();
        for result in results {
            if let Ok(event) = serde_json::from_str::<SecurityEvent>(&result) {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Record session creation
    pub async fn record_session_created(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        duration_secs: u64,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        // Store session metadata for analytics
        let key = format!("analytics:session:{}", session_id);
        let metadata = serde_json::json!({
            "user_id": user_id,
            "created_at": Utc::now(),
            "duration_secs": duration_secs,
        });

        let _: () = redis.set_ex(&key, metadata.to_string(), (self.retention_days * 24 * 60 * 60) as u64).await?;

        // Increment global session counter
        let counter_key = "analytics:total_sessions";
        let _: () = redis.incr(counter_key, 1).await?;

        info!("Session {} created for user {} (duration: {}s)", session_id, user_id, duration_secs);

        Ok(())
    }

    /// Record session termination
    pub async fn record_session_terminated(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        actual_duration_secs: u64,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        // Update session metadata
        let key = format!("analytics:session:{}", session_id);
        let metadata = serde_json::json!({
            "user_id": user_id,
            "terminated_at": Utc::now(),
            "actual_duration_secs": actual_duration_secs,
        });

        let _: () = redis.set_ex(&key, metadata.to_string(), (self.retention_days * 24 * 60 * 60) as u64).await?;

        // Store duration for statistics
        let duration_key = "analytics:session_durations";
        let _: () = redis.lpush(&duration_key, actual_duration_secs).await?;
        let _: () = redis.ltrim(&duration_key, 0, 999).await?; // Keep last 1000

        info!("Session {} terminated for user {} (actual duration: {}s)", session_id, user_id, actual_duration_secs);

        Ok(())
    }

    /// Get session duration statistics
    pub async fn get_session_duration_stats(
        &self,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<SessionDurationStats, SessionError> {
        let key = "analytics:session_durations";
        let durations: Vec<u64> = redis.lrange(&key, 0, -1).await.unwrap_or_default();

        if durations.is_empty() {
            return Ok(SessionDurationStats {
                avg_duration_secs: 0.0,
                min_duration_secs: 0,
                max_duration_secs: 0,
                median_duration_secs: 0,
                total_sessions: 0,
            });
        }

        let sum: u64 = durations.iter().sum();
        let count = durations.len();
        let avg = sum as f64 / count as f64;

        let mut sorted = durations.clone();
        sorted.sort_unstable();

        let min = *sorted.first().unwrap_or(&0);
        let max = *sorted.last().unwrap_or(&0);
        let median = if count % 2 == 0 {
            (sorted[count / 2 - 1] + sorted[count / 2]) / 2
        } else {
            sorted[count / 2]
        };

        Ok(SessionDurationStats {
            avg_duration_secs: avg,
            min_duration_secs: min,
            max_duration_secs: max,
            median_duration_secs: median,
            total_sessions: count,
        })
    }

    /// Get security events summary
    pub async fn get_security_events_summary(
        &self,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<HashMap<SecurityEventType, usize>, SessionError> {
        let mut summary = HashMap::new();

        let event_types = vec![
            SecurityEventType::FailedLogin,
            SecurityEventType::SuccessfulLogin,
            SecurityEventType::SessionCreated,
            SecurityEventType::SessionExpired,
            SecurityEventType::SessionTerminated,
            SecurityEventType::TokenRefresh,
            SecurityEventType::FailedTokenRefresh,
            SecurityEventType::NewDevice,
            SecurityEventType::NewLocation,
            SecurityEventType::SuspiciousActivity,
            SecurityEventType::AccountLocked,
            SecurityEventType::AccountUnlocked,
            SecurityEventType::PasswordChanged,
            SecurityEventType::EmailChanged,
            SecurityEventType::TwoFactorEnabled,
            SecurityEventType::TwoFactorDisabled,
        ];

        for event_type in event_types {
            let key = format!("analytics:security_events:{}", event_type.to_string());
            let count: usize = redis.get(&key).await.unwrap_or(0);
            if count > 0 {
                summary.insert(event_type, count);
            }
        }

        Ok(summary)
    }

    /// Detect suspicious activity patterns
    pub async fn detect_suspicious_activity(
        &self,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Vec<String>, SessionError> {
        let mut alerts = Vec::new();

        // Get recent security events
        let events = self.get_user_security_events(user_id, 100, redis).await?;

        // Check for multiple failed logins
        let failed_logins = events
            .iter()
            .filter(|e| e.event_type == SecurityEventType::FailedLogin)
            .count();

        if failed_logins > 5 {
            alerts.push(format!("Multiple failed login attempts: {}", failed_logins));
        }

        // Check for rapid location changes
        let mut locations = Vec::new();
        for event in &events {
            if let Some(ref loc) = event.location {
                if !locations.contains(loc) {
                    locations.push(loc.clone());
                }
            }
        }

        if locations.len() > 3 {
            alerts.push(format!("Multiple locations detected: {}", locations.len()));
        }

        // Check for multiple new devices
        let new_devices = events
            .iter()
            .filter(|e| e.event_type == SecurityEventType::NewDevice)
            .count();

        if new_devices > 3 {
            alerts.push(format!("Multiple new devices: {}", new_devices));
        }

        Ok(alerts)
    }
}

impl ToString for SecurityEventType {
    fn to_string(&self) -> String {
        match self {
            SecurityEventType::FailedLogin => "failed_login".to_string(),
            SecurityEventType::SuccessfulLogin => "successful_login".to_string(),
            SecurityEventType::SessionCreated => "session_created".to_string(),
            SecurityEventType::SessionExpired => "session_expired".to_string(),
            SecurityEventType::SessionTerminated => "session_terminated".to_string(),
            SecurityEventType::TokenRefresh => "token_refresh".to_string(),
            SecurityEventType::FailedTokenRefresh => "failed_token_refresh".to_string(),
            SecurityEventType::NewDevice => "new_device".to_string(),
            SecurityEventType::NewLocation => "new_location".to_string(),
            SecurityEventType::SuspiciousActivity => "suspicious_activity".to_string(),
            SecurityEventType::AccountLocked => "account_locked".to_string(),
            SecurityEventType::AccountUnlocked => "account_unlocked".to_string(),
            SecurityEventType::PasswordChanged => "password_changed".to_string(),
            SecurityEventType::EmailChanged => "email_changed".to_string(),
            SecurityEventType::TwoFactorEnabled => "two_factor_enabled".to_string(),
            SecurityEventType::TwoFactorDisabled => "two_factor_disabled".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_creation() {
        let user_id = Uuid::new_v4();
        let event = SecurityEvent::new(SecurityEventType::FailedLogin, user_id)
            .with_ip("192.168.1.1".to_string())
            .with_user_agent("Mozilla/5.0".to_string());

        assert_eq!(event.event_type, SecurityEventType::FailedLogin);
        assert_eq!(event.user_id, user_id);
        assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_event_type_to_string() {
        assert_eq!(SecurityEventType::FailedLogin.to_string(), "failed_login");
        assert_eq!(SecurityEventType::SessionCreated.to_string(), "session_created");
    }

    #[test]
    fn test_analytics_tracker_creation() {
        let tracker = AnalyticsTracker::new(90);
        assert_eq!(tracker.retention_days, 90);

        let default_tracker = AnalyticsTracker::default();
        assert_eq!(default_tracker.retention_days, 90);
    }
}
