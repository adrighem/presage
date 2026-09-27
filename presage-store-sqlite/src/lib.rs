use std::str::FromStr;

use presage::{
    libsignal_service::{
        libsignal_account_keys::AccountEntropyPool, prelude::MasterKey, protocol::SenderCertificate,
    },
    store::{StateStore, Store},
};
use protocol::{IdentityType, SqliteProtocolStore};
use sqlx::{
    SqlitePool, query, query_scalar,
    sqlite::{SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

mod client_identity;
mod client_outbox;
mod content;
mod data;
mod error;
mod protocol;

pub use client_identity::IdentityChangeNotice;
pub use client_outbox::{ClientOutboxKind, ClientOutboxMessage};
pub use error::SqliteStoreError;
pub use presage::model::identity::OnNewIdentity;
pub use sqlx::sqlite::SqliteConnectOptions;

use crate::error::SqlxErrorExt;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pub(crate) db: SqlitePool,
    pub(crate) trust_new_identities: OnNewIdentity,
}

impl SqliteStore {
    pub async fn open(
        url: &str,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        Self::open_with_passphrase(url, None, trust_new_identities).await
    }

    pub async fn open_with_passphrase(
        url: &str,
        passphrase: Option<&str>,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        // Escape the passphrase.
        let passphrase = passphrase.map(|p| p.replace("'", "''"));

        let options: SqliteConnectOptions = url.parse()?;
        let options = options.create_if_missing(true).foreign_keys(true);
        let options = if let Some(passphrase) = &passphrase {
            options.pragma("key", format!("'{passphrase}'"))
        } else {
            options
        };
        Self::open_with_options(options.clone(), trust_new_identities.clone()).await
    }

    pub async fn open_with_options(
        options: SqliteConnectOptions,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        let options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);
        // Signal protocol state uses read-modify-write transactions. Multiple
        // SQLite connections can race those transactions and return
        // SQLITE_BUSY even with WAL and a busy timeout, so serialize access at
        // the pool boundary.
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;

        sqlx::migrate!().run(&db).await?;
        Ok(Self {
            db,
            trust_new_identities,
        })
    }
}

impl Store for SqliteStore {
    type Error = SqliteStoreError;

    type AciStore = SqliteProtocolStore;

    type PniStore = SqliteProtocolStore;

    async fn clear(&mut self) -> Result<(), SqliteStoreError> {
        query!("DELETE FROM kv").execute(&self.db).await?;
        Ok(())
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity: IdentityType::Aci,
        }
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity: IdentityType::Pni,
        }
    }
}

impl StateStore for SqliteStore {
    type StateStoreError = SqliteStoreError;

    async fn load_registration_data(
        &self,
    ) -> Result<Option<presage::manager::RegistrationData>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'registration'")
            .fetch_optional(&self.db)
            .await?
            .map(|value| serde_json::from_slice(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_registration_data(
        &mut self,
        state: &presage::manager::RegistrationData,
    ) -> Result<(), Self::StateStoreError> {
        let value = serde_json::to_string(state)?;
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('registration', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn is_registered(&self) -> bool {
        self.load_registration_data().await.ok().flatten().is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), Self::StateStoreError> {
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM kv WHERE key = 'registration'")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM sessions")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM identities")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM signed_pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM kyber_pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM sender_keys")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        let key = IdentityType::Aci.identity_key_pair_key();
        let value = key_pair.serialize();
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        let key = IdentityType::Pni.identity_key_pair_key();
        let value = key_pair.serialize();
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn sender_certificate(&self) -> Result<Option<SenderCertificate>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'sender_certificate' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| SenderCertificate::deserialize(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_sender_certificate(
        &self,
        certificate: &SenderCertificate,
    ) -> Result<(), Self::StateStoreError> {
        let value = certificate.serialized()?;
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('sender_certificate', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn fetch_master_key(&self) -> Result<Option<MasterKey>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'master_key' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| MasterKey::from_slice(&value))
            .transpose()
            .map_err(|_| SqliteStoreError::InvalidFormat)
    }

    async fn store_master_key(
        &self,
        master_key: Option<&MasterKey>,
    ) -> Result<(), Self::StateStoreError> {
        let value = master_key.map(|k| &k.inner[..]);
        if let Some(value) = value {
            query!(
                "INSERT OR REPLACE INTO kv (key, value) VALUES ('master_key', ?)",
                value
            )
            .execute(&self.db)
            .await?;
        } else {
            query!("DELETE FROM kv WHERE key = 'master_key'")
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }

    async fn fetch_account_entropy_pool(
        &self,
    ) -> Result<Option<AccountEntropyPool>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'account_entropy_pool' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| {
                AccountEntropyPool::from_str(
                    str::from_utf8(&value).map_err(|_| SqliteStoreError::InvalidFormat)?,
                )
                .map_err(|_| SqliteStoreError::InvalidFormat)
            })
            .transpose()
            .map_err(|_| SqliteStoreError::InvalidFormat)
    }

    async fn store_account_entropy_pool(
        &self,
        aep: Option<&AccountEntropyPool>,
    ) -> Result<(), Self::StateStoreError> {
        let value = aep.map(|k| k.to_string().into_bytes());
        if let Some(value) = value {
            query!(
                "INSERT OR REPLACE INTO kv (key, value) VALUES ('account_entropy_pool', ?)",
                value
            )
            .execute(&self.db)
            .await?;
        } else {
            query!("DELETE FROM kv WHERE key = 'account_entropy_pool'")
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::{Path, PathBuf},
        time::Duration,
    };

    struct TestDatabase(PathBuf);

    impl TestDatabase {
        fn new() -> Self {
            Self(
                std::env::temp_dir()
                    .join(format!("presage-store-pool-{}.db3", rand::random::<u64>())),
            )
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
            let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
        }
    }

    #[tokio::test]
    async fn sqlite_store_serializes_pool_access() {
        let store = SqliteStore::open("sqlite::memory:", OnNewIdentity::TrustUnverified)
            .await
            .unwrap();

        assert_eq!(store.db.options().get_max_connections(), 1);
        store.db.close().await;
    }

    #[tokio::test]
    async fn sqlite_store_queues_a_writer_behind_an_active_transaction() {
        let database = TestDatabase::new();
        let options = SqliteConnectOptions::new()
            .filename(database.path())
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(20));
        let store = SqliteStore::open_with_options(options, OnNewIdentity::TrustUnverified)
            .await
            .unwrap();
        if store.db.options().get_max_connections() > 1 {
            let first_connection = store.db.acquire().await.unwrap();
            let second_connection = store.db.acquire().await.unwrap();
            drop(first_connection);
            drop(second_connection);
            assert!(store.db.size() >= 2);
        }
        let mut transaction = store.db.begin().await.unwrap();
        query("INSERT OR REPLACE INTO kv (key, value) VALUES ('writer-a', X'01')")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let mut second_write = Box::pin(
            query("INSERT OR REPLACE INTO kv (key, value) VALUES ('writer-b', X'02')")
                .execute(&store.db),
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut second_write)
                .await
                .is_err()
        );
        transaction.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), second_write)
            .await
            .unwrap()
            .unwrap();
        store.db.close().await;
    }
}
