//! Device trust and fingerprinting
//!
//! Manages trusted devices for enhanced security:
//! - Device fingerprinting
//! - Trust level management
//! - Enhanced sessions for trusted devices
//! - Security alerts for new devices

use crate::error::SessionError;
use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Device trust level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// New/unknown device - require additional verification
    Untrusted,
    /// Recognized device - standard security
    Recognized,
    /// Trusted device - extended session duration
    Trusted,
    /// Compromised device - block access
    Compromised,
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Untrusted => write!(f, "untrusted"),
            TrustLevel::Recognized => write!(f, "recognized"),
            TrustLevel::Trusted => write!(f, "trusted"),
            TrustLevel::Compromised => write!(f, "compromised"),
        }
    }
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Unique device identifier (fingerprint hash)
    pub device_id: String,
    /// User agent string
    pub user_agent: String,
    /// IP address
    pub ip_address: String,
    /// Device type (mobile, desktop, tablet)
    pub device_type: String,
    /// Browser name
    pub browser: Option<String>,
    /// Operating system
    pub os: Option<String>,
    /// Screen resolution (for fingerprinting)
    pub screen_resolution: Option<String>,
    /// Timezone
    pub timezone: Option<String>,
    /// Language
    pub language: Option<String>,
}

impl DeviceInfo {
    /// Create device info from headers and fingerprint data
    pub fn new(
        device_id: String,
        user_agent: String,
        ip_address: String,
        device_type: String,
    ) -> Self {
        Self {
            device_id,
            user_agent,
            ip_address,
            device_type,
            browser: None,
            os: None,
            screen_resolution: None,
            timezone: None,
            language: None,
        }
    }

    /// Create fingerprint from device characteristics
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.user_agent.as_bytes());
        hasher.update(self.device_type.as_bytes());

        if let Some(ref browser) = self.browser {
            hasher.update(browser.as_bytes());
        }
        if let Some(ref os) = self.os {
            hasher.update(os.as_bytes());
        }
        if let Some(ref resolution) = self.screen_resolution {
            hasher.update(resolution.as_bytes());
        }
        if let Some(ref timezone) = self.timezone {
            hasher.update(timezone.as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }
}

/// Trusted device record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    /// Device ID
    pub device_id: String,
    /// User ID
    pub user_id: Uuid,
    /// Device information
    pub device_info: DeviceInfo,
    /// Trust level
    pub trust_level: TrustLevel,
    /// When device was first seen
    pub first_seen: DateTime<Utc>,
    /// When device was last used
    pub last_used: DateTime<Utc>,
    /// When device was marked as trusted
    pub trusted_at: Option<DateTime<Utc>>,
    /// Device name (user-friendly)
    pub device_name: Option<String>,
    /// Number of successful logins from this device
    pub login_count: u32,
}

impl TrustedDevice {
    /// Create new untrusted device
    pub fn new(device_id: String, user_id: Uuid, device_info: DeviceInfo) -> Self {
        Self {
            device_id,
            user_id,
            device_info,
            trust_level: TrustLevel::Untrusted,
            first_seen: Utc::now(),
            last_used: Utc::now(),
            trusted_at: None,
            device_name: None,
            login_count: 1,
        }
    }

    /// Mark device as trusted
    pub fn mark_trusted(&mut self, device_name: Option<String>) {
        self.trust_level = TrustLevel::Trusted;
        self.trusted_at = Some(Utc::now());
        self.device_name = device_name;
        info!("Device {} marked as trusted", self.device_id);
    }

    /// Update last used timestamp
    pub fn touch(&mut self) {
        self.last_used = Utc::now();
        self.login_count += 1;
    }

    /// Check if device should be auto-trusted (e.g., after N successful logins)
    pub fn should_auto_trust(&self, min_login_count: u32) -> bool {
        self.trust_level == TrustLevel::Untrusted && self.login_count >= min_login_count
    }
}

/// Device manager for trust management
pub struct DeviceManager {
    /// Minimum logins before auto-trust
    min_login_count_for_trust: u32,
    /// Maximum trusted devices per user
    max_trusted_devices: usize,
}

impl DeviceManager {
    /// Create new device manager
    pub fn new(min_login_count_for_trust: u32, max_trusted_devices: usize) -> Self {
        Self {
            min_login_count_for_trust,
            max_trusted_devices,
        }
    }

    /// Get device by ID
    pub async fn get_device(
        &self,
        device_id: &str,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Option<TrustedDevice>, SessionError> {
        let key = format!("user:{}:device:{}", user_id, device_id);

        let value: Option<String> = redis.get(&key).await?;

        if let Some(json) = value {
            let device = serde_json::from_str::<TrustedDevice>(&json)?;
            Ok(Some(device))
        } else {
            Ok(None)
        }
    }

    /// Save device
    pub async fn save_device(
        &self,
        device: &TrustedDevice,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let key = format!("user:{}:device:{}", device.user_id, device.device_id);
        let value = serde_json::to_string(device)?;

        // Store device with 90-day expiration
        let _: () = redis.set_ex(&key, value, 90 * 24 * 60 * 60).await?;

        // Add to user's device list
        let list_key = format!("user:{}:devices", device.user_id);
        let _: () = redis.sadd(&list_key, &device.device_id).await?;
        let _: () = redis.expire(&list_key, 90 * 24 * 60 * 60).await?;

        debug!("Saved device {} for user {}", device.device_id, device.user_id);

        Ok(())
    }

    /// Get all devices for a user
    pub async fn get_user_devices(
        &self,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<Vec<TrustedDevice>, SessionError> {
        let list_key = format!("user:{}:devices", user_id);

        let device_ids: Vec<String> = redis.smembers(&list_key).await.unwrap_or_default();

        let mut devices = Vec::new();
        for device_id in device_ids {
            if let Some(device) = self.get_device(&device_id, user_id, redis).await? {
                devices.push(device);
            }
        }

        // Sort by last used (most recent first)
        devices.sort_by(|a, b| b.last_used.cmp(&a.last_used));

        Ok(devices)
    }

    /// Register or update device
    pub async fn register_device(
        &self,
        device_id: String,
        user_id: Uuid,
        device_info: DeviceInfo,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<TrustedDevice, SessionError> {
        if let Some(mut device) = self.get_device(&device_id, user_id, redis).await? {
            // Update existing device
            device.touch();

            // Auto-trust if meets criteria
            if device.should_auto_trust(self.min_login_count_for_trust) {
                device.mark_trusted(Some(format!(
                    "{} - Auto-trusted",
                    device.device_info.device_type
                )));
                info!("Auto-trusted device {} after {} logins", device_id, device.login_count);
            }

            self.save_device(&device, redis).await?;
            Ok(device)
        } else {
            // Create new device
            let device = TrustedDevice::new(device_id, user_id, device_info);
            self.save_device(&device, redis).await?;

            info!("Registered new device {} for user {}", device.device_id, user_id);

            Ok(device)
        }
    }

    /// Mark device as trusted
    pub async fn trust_device(
        &self,
        device_id: &str,
        user_id: Uuid,
        device_name: Option<String>,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let mut device = self
            .get_device(device_id, user_id, redis)
            .await?
            .ok_or_else(|| SessionError::DeviceNotFound(device_id.to_string()))?;

        // Enforce max trusted devices limit
        let trusted_devices = self
            .get_user_devices(user_id, redis)
            .await?
            .into_iter()
            .filter(|d| d.trust_level == TrustLevel::Trusted)
            .count();

        if trusted_devices >= self.max_trusted_devices {
            return Err(SessionError::TooManyTrustedDevices);
        }

        device.mark_trusted(device_name);
        self.save_device(&device, redis).await?;

        Ok(())
    }

    /// Revoke trust from device
    pub async fn untrust_device(
        &self,
        device_id: &str,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let mut device = self
            .get_device(device_id, user_id, redis)
            .await?
            .ok_or_else(|| SessionError::DeviceNotFound(device_id.to_string()))?;

        device.trust_level = TrustLevel::Untrusted;
        device.trusted_at = None;

        self.save_device(&device, redis).await?;

        info!("Revoked trust from device {}", device_id);

        Ok(())
    }

    /// Mark device as compromised (blocks all access)
    pub async fn mark_compromised(
        &self,
        device_id: &str,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), SessionError> {
        let mut device = self
            .get_device(device_id, user_id, redis)
            .await?
            .ok_or_else(|| SessionError::DeviceNotFound(device_id.to_string()))?;

        device.trust_level = TrustLevel::Compromised;

        self.save_device(&device, redis).await?;

        warn!("Device {} marked as compromised", device_id);

        Ok(())
    }

    /// Check if device is trusted
    pub async fn is_trusted(
        &self,
        device_id: &str,
        user_id: Uuid,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<bool, SessionError> {
        if let Some(device) = self.get_device(device_id, user_id, redis).await? {
            Ok(device.trust_level == TrustLevel::Trusted)
        } else {
            Ok(false)
        }
    }

    /// Get session duration multiplier based on device trust
    pub fn get_session_duration_multiplier(&self, trust_level: TrustLevel) -> f32 {
        match trust_level {
            TrustLevel::Trusted => 3.0,      // 3x longer sessions
            TrustLevel::Recognized => 1.0,   // Normal duration
            TrustLevel::Untrusted => 0.5,    // 50% shorter sessions
            TrustLevel::Compromised => 0.0,  // No session
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_levels() {
        assert_eq!(TrustLevel::Trusted.to_string(), "trusted");
        assert_eq!(TrustLevel::Untrusted.to_string(), "untrusted");
    }

    #[test]
    fn test_device_creation() {
        let device_info = DeviceInfo::new(
            "device123".to_string(),
            "Mozilla/5.0".to_string(),
            "192.168.1.1".to_string(),
            "desktop".to_string(),
        );

        let user_id = Uuid::new_v4();
        let device = TrustedDevice::new("device123".to_string(), user_id, device_info);

        assert_eq!(device.trust_level, TrustLevel::Untrusted);
        assert_eq!(device.login_count, 1);
    }

    #[test]
    fn test_auto_trust() {
        let device_info = DeviceInfo::new(
            "device123".to_string(),
            "Mozilla/5.0".to_string(),
            "192.168.1.1".to_string(),
            "desktop".to_string(),
        );

        let user_id = Uuid::new_v4();
        let mut device = TrustedDevice::new("device123".to_string(), user_id, device_info);

        assert!(!device.should_auto_trust(5));

        device.login_count = 5;
        assert!(device.should_auto_trust(5));
    }

    #[test]
    fn test_session_duration_multiplier() {
        let manager = DeviceManager::new(5, 10);

        assert_eq!(manager.get_session_duration_multiplier(TrustLevel::Trusted), 3.0);
        assert_eq!(manager.get_session_duration_multiplier(TrustLevel::Recognized), 1.0);
        assert_eq!(manager.get_session_duration_multiplier(TrustLevel::Untrusted), 0.5);
        assert_eq!(manager.get_session_duration_multiplier(TrustLevel::Compromised), 0.0);
    }
}
