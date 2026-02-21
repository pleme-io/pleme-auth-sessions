pub mod activity;
pub mod analytics;
pub mod config;
pub mod device;
pub mod error;
pub mod middleware;
pub mod models;
pub mod service;

// Re-export commonly used types
pub use activity::{ActivityConfig, ActivityTracker, ActivityType, SessionActivity};
pub use analytics::{AnalyticsTracker, SecurityEvent, SecurityEventType};
pub use config::SessionConfig;
pub use device::{DeviceInfo, DeviceManager, TrustLevel, TrustedDevice};
pub use error::SessionError;
pub use middleware::{
    auth_middleware, optional_auth_middleware, OptionalSessionContext, SessionContext,
    SessionMiddlewareState,
};
pub use models::{Session, SessionData};
pub use service::SessionService;
