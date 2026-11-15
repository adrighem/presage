use presage::{
    libsignal_service::{
        prelude::phonenumber,
        protocol::{InvalidDeviceId, SignalProtocolError},
    },
    store::{StoreError, TransientStoreError},
};
use tracing::error;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SqliteStoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    PhoneNumber(#[from] phonenumber::ParseError),
    #[error("conversation error")]
    InvalidFormat,
    #[error(transparent)]
    Protocol(#[from] SignalProtocolError),
    #[error("invalid device ID: {0}")]
    InvalidDeviceId(#[from] InvalidDeviceId),
}

impl StoreError for SqliteStoreError {}

impl SqliteStoreError {
    /// Whether retrying the failed operation may succeed: a pool timeout, a busy or locked
    /// database, or an IO error.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Db(error) => sqlx_error_is_transient(error),
            Self::Io(_) => true,
            _ => false,
        }
    }
}

fn sqlx_error_is_transient(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::PoolTimedOut | sqlx::Error::Io(_) => true,
        // SQLite reports extended result codes; the low byte is the primary code.
        sqlx::Error::Database(error) => error
            .code()
            .and_then(|code| code.parse::<i32>().ok())
            .is_some_and(|code| matches!(code & 0xff, SQLITE_BUSY | SQLITE_LOCKED)),
        _ => false,
    }
}

const SQLITE_BUSY: i32 = 5;
const SQLITE_LOCKED: i32 = 6;

fn transient_protocol_error(error: impl ToString) -> SignalProtocolError {
    SignalProtocolError::ApplicationCallbackError(
        "presage sqlite store",
        Box::new(TransientStoreError(error.to_string())),
    )
}

impl From<SqliteStoreError> for presage::libsignal_service::protocol::SignalProtocolError {
    fn from(error: SqliteStoreError) -> Self {
        error!(%error, "presage sqlite store error");
        if error.is_transient() {
            transient_protocol_error(error)
        } else {
            Self::InvalidState("presage sqlite store error", error.to_string())
        }
    }
}

pub(crate) trait SqlxErrorExt<T> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError>;
}

impl<T> SqlxErrorExt<T> for Result<T, sqlx::Error> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError> {
        self.map_err(|error| {
            if sqlx_error_is_transient(&error) {
                transient_protocol_error(error)
            } else {
                SignalProtocolError::InvalidState("sqlite", error.to_string())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use presage::libsignal_service::push_service::ServiceError;

    use super::*;

    #[test]
    fn transient_sqlx_errors_reach_the_receive_loop_as_transient() {
        let transient: Result<(), _> = Err(sqlx::Error::PoolTimedOut);
        let error = ServiceError::from(transient.into_protocol_error().unwrap_err());
        assert!(TransientStoreError::is_cause_of(&error));

        let permanent: Result<(), _> = Err(sqlx::Error::RowNotFound);
        let error = ServiceError::from(permanent.into_protocol_error().unwrap_err());
        assert!(!TransientStoreError::is_cause_of(&error));
    }

    #[test]
    fn store_errors_classify_transience() {
        assert!(SqliteStoreError::Db(sqlx::Error::PoolTimedOut).is_transient());
        assert!(!SqliteStoreError::Db(sqlx::Error::PoolClosed).is_transient());
        assert!(!SqliteStoreError::InvalidFormat.is_transient());
    }
}
