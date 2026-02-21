use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Sessão não encontrada")]
    SessionNotFound,

    #[error("Sessão expirada")]
    SessionExpired,

    #[error("Sessão inválida: {0}")]
    InvalidSession(String),

    #[error("Erro ao acessar Redis: {0}")]
    RedisError(String),

    #[error("Erro ao serializar sessão: {0}")]
    SerializationError(String),

    #[error("Erro ao desserializar sessão: {0}")]
    DeserializationError(String),

    #[error("Token de atualização não encontrado")]
    RefreshTokenNotFound,

    #[error("Token de atualização inválido")]
    InvalidRefreshToken,

    #[error("Limite de sessões excedido (máximo: {0})")]
    SessionLimitExceeded(usize),

    #[error("Dispositivo não encontrado: {0}")]
    DeviceNotFound(String),

    #[error("Muitos dispositivos confiáveis (máximo permitido)")]
    TooManyTrustedDevices,
}

impl From<redis::RedisError> for SessionError {
    fn from(err: redis::RedisError) -> Self {
        SessionError::RedisError(err.to_string())
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(err: serde_json::Error) -> Self {
        SessionError::SerializationError(err.to_string())
    }
}
