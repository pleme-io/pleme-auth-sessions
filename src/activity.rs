//! Session activity tracking
//!
//! Tracks user activity to enable:
//! - Auto-extension of sessions on activity
//! - Idle timeout detection
//! - Activity-based security policies

use crate::error::SessionError;
use chrono::{DateTime, Duration, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

/// Activity event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ActivityType {
    /// API request (GET, POST, etc.)
    ApiRequest,
    /// GraphQL query/mutation
    GraphqlOperation,
    /// Page view or navigation
    PageView,
    /// User interaction (click, scroll, etc.)
    Interaction,
    /// Token refresh
    TokenRefresh,
    /// Login/authentication
    Login,
    /// Sensitive operation (payment, profile update)
    SensitiveOperation,
}

/// Session activity record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionActivity {
    /// When the activity occurred
    pub timestamp: DateTime<Utc>,
    /// Type of activity
    pub activity_type: ActivityType,
    /// Optional metadata (e.g., endpoint, operation name)
    pub metadata: Option<String>,
}

impl SessionActivity {
    /// Create new activity record
    pub fn new(activity_type: ActivityType, metadata: Option<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            activity_type,
            metadata,
        }
    }
}

/// Configuration for activity tracking
#[derive(Debug, Clone)]
pub struct ActivityConfig {
    /// How long to keep activity history (default: 24 hours)
    pub history_retention: Duration,
    /// Idle timeout duration (default: 30 minutes)
    pub idle_timeout: Duration,
    /// Auto-extend session on activity (default: true)
    pub auto_extend_on_activity: bool,
    /// Extension duration when auto-extending (default: session duration)
    pub extension_duration: Duration,
    /// Minimum time between auto-extensions (default: 5 minutes)
    pub min_extension_interval: Duration,
}

impl Default for ActivityConfig {
    fn default() -> Self {
        Self {
            history_retention: Duration::hours(24),
            idle_timeout: Duration::minutes(30),
            auto_extend_on_activity: true,
            extension_duration: Duration::days(30),
            min_extension_interval: Duration::minutes(5),
        }
    }
}

/// Activity tracker for sessions
pub struct ActivityTracker {
    config: ActivityConfig,
}

impl ActivityTracker {
    /// Create new activity tracker
    pub fn new(config: ActivityConfig) -> Self {
        Self { config }
    }

    /// Record activity for a session
    pub async fn record_activity(
        &self,
        session_id: Uuid,
        activity_type: ActivityType,
        metadata: Option<String>,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let activity = SessionActivity::new(activity_type, metadata);

        // Store activity in Redis sorted set (sorted by timestamp)
        let key = format!("session:{}:activity", session_id);
        let score = activity.timestamp.timestamp();
        let value = serde_json::to_string(&activity)?;

        let _: () = redis.zadd(&key, value, score).await?;

        // Set expiration on activity key
        let retention_secs = self.config.history_retention.num_seconds() as u64;
        let _: () = redis.expire(&key, retention_secs as i64).await?;

        // Clean up old activity records
        let cutoff = (Utc::now() - self.config.history_retention).timestamp();
        let _: () = redis.zrembyscore(&key, "-inf", cutoff).await?;

        debug!("Recorded activity for session {}: {:?}", session_id, activity.activity_type);

        Ok(())
    }

    /// Get last activity timestamp for session
    pub async fn get_last_activity(
        &self,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Option<DateTime<Utc>>, SessionError> {
        let key = format!("session:{}:activity", session_id);

        // Get most recent activity (highest score)
        let results: Vec<(String, f64)> = redis
            .zrevrange_withscores(&key, 0, 0)
            .await
            .unwrap_or_default();

        if let Some((_, score)) = results.first() {
            let timestamp = DateTime::from_timestamp(*score as i64, 0)
                .ok_or_else(|| SessionError::InvalidSession("Invalid timestamp".to_string()))?;
            Ok(Some(timestamp))
        } else {
            Ok(None)
        }
    }

    /// Check if session is idle (no activity within idle timeout)
    pub async fn is_idle(
        &self,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<bool, SessionError> {
        if let Some(last_activity) = self.get_last_activity(session_id, redis).await? {
            let idle_duration = Utc::now() - last_activity;
            Ok(idle_duration > self.config.idle_timeout)
        } else {
            // No activity recorded - consider idle
            Ok(true)
        }
    }

    /// Get session activity history
    pub async fn get_activity_history(
        &self,
        session_id: Uuid,
        limit: usize,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Vec<SessionActivity>, SessionError> {
        let key = format!("session:{}:activity", session_id);

        // Get recent activities (most recent first)
        let results: Vec<String> = redis
            .zrevrange(&key, 0, (limit - 1) as isize)
            .await
            .unwrap_or_default();

        let mut activities = Vec::new();
        for result in results {
            if let Ok(activity) = serde_json::from_str::<SessionActivity>(&result) {
                activities.push(activity);
            }
        }

        Ok(activities)
    }

    /// Check if session should be auto-extended based on recent activity
    pub async fn should_extend(
        &self,
        session_id: Uuid,
        last_extension: DateTime<Utc>,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<bool, SessionError> {
        if !self.config.auto_extend_on_activity {
            return Ok(false);
        }

        // Don't extend if recently extended
        if Utc::now() - last_extension < self.config.min_extension_interval {
            return Ok(false);
        }

        // Check for recent activity
        if let Some(last_activity) = self.get_last_activity(session_id, redis).await? {
            let time_since_activity = Utc::now() - last_activity;

            // Extend if activity within idle timeout
            Ok(time_since_activity <= self.config.idle_timeout)
        } else {
            Ok(false)
        }
    }

    /// Get activity statistics for session
    pub async fn get_statistics(
        &self,
        session_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<ActivityStatistics, SessionError> {
        let key = format!("session:{}:activity", session_id);

        // Get all activities
        let count: usize = redis.zcard(&key).await.unwrap_or(0);

        let last_activity = self.get_last_activity(session_id, redis).await?;

        let is_idle = self.is_idle(session_id, redis).await?;

        // Get activities by type
        let activities = self.get_activity_history(session_id, 100, redis).await?;
        let mut by_type = std::collections::HashMap::new();
        for activity in activities {
            *by_type.entry(activity.activity_type).or_insert(0) += 1;
        }

        Ok(ActivityStatistics {
            total_activities: count,
            last_activity,
            is_idle,
            activities_by_type: by_type,
        })
    }
}

/// Activity statistics for a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityStatistics {
    /// Total number of activities recorded
    pub total_activities: usize,
    /// Timestamp of last activity
    pub last_activity: Option<DateTime<Utc>>,
    /// Whether session is currently idle
    pub is_idle: bool,
    /// Count of activities by type
    pub activities_by_type: std::collections::HashMap<ActivityType, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_creation() {
        let activity = SessionActivity::new(ActivityType::ApiRequest, Some("GET /api/users".to_string()));
        assert_eq!(activity.activity_type, ActivityType::ApiRequest);
        assert_eq!(activity.metadata, Some("GET /api/users".to_string()));
    }

    #[test]
    fn test_default_config() {
        let config = ActivityConfig::default();
        assert_eq!(config.history_retention, Duration::hours(24));
        assert_eq!(config.idle_timeout, Duration::minutes(30));
        assert!(config.auto_extend_on_activity);
    }
}
