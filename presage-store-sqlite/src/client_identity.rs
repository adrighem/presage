use presage::libsignal_service::protocol::{IdentityKey, ServiceId};
use sqlx::{Row, query, query_scalar};

use crate::{SqliteStore, SqliteStoreError, protocol::IdentityType};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityChangeNotice {
    pub address: String,
    pub verified: bool,
}

impl SqliteStore {
    pub async fn initialize_identity_change_tracking(&self) -> Result<(), SqliteStoreError> {
        query(
            "CREATE TABLE IF NOT EXISTS client_identity_changes (\
             address TEXT NOT NULL, identity TEXT NOT NULL, \
             new_record BLOB NOT NULL, verified BOOLEAN NOT NULL, \
             PRIMARY KEY (address, identity))",
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn identity_change_notices(
        &self,
    ) -> Result<Vec<IdentityChangeNotice>, SqliteStoreError> {
        query("SELECT address, verified FROM client_identity_changes ORDER BY address")
            .fetch_all(&self.db)
            .await?
            .into_iter()
            .map(|row| {
                Ok(IdentityChangeNotice {
                    address: row.try_get("address")?,
                    verified: row.try_get("verified")?,
                })
            })
            .collect()
    }

    pub async fn dismiss_identity_change(&self, address: &str) -> Result<(), SqliteStoreError> {
        query("DELETE FROM client_identity_changes WHERE address = ? AND verified = false")
            .bind(address)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    pub async fn accept_identity_change(&self, address: &str) -> Result<bool, SqliteStoreError> {
        let mut transaction = self.db.begin().await?;
        let change = query(
            "SELECT identity, new_record FROM client_identity_changes \
             WHERE address = ? AND verified = true",
        )
        .bind(address)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(change) = change else {
            return Ok(false);
        };
        let identity: String = change.try_get("identity")?;
        let new_record: Vec<u8> = change.try_get("new_record")?;

        query("UPDATE identities SET record = ? WHERE address = ? AND identity = ?")
            .bind(&new_record)
            .bind(address)
            .bind(&identity)
            .execute(&mut *transaction)
            .await?;
        query("DELETE FROM sessions WHERE address = ? AND identity = ?")
            .bind(address)
            .bind(&identity)
            .execute(&mut *transaction)
            .await?;
        query("DELETE FROM sender_keys WHERE address = ? AND identity = ?")
            .bind(address)
            .bind(&identity)
            .execute(&mut *transaction)
            .await?;

        if let Some(service_id) = ServiceId::parse_from_service_id_string(address) {
            query(
                "UPDATE contacts_verification_state \
                 SET identity_key = ?, is_verified = false \
                 WHERE destination_aci = ? OR destination_aci = ?",
            )
            .bind(&new_record)
            .bind(service_id.raw_uuid())
            .bind(address)
            .execute(&mut *transaction)
            .await?;
        }
        query("DELETE FROM client_identity_changes WHERE address = ? AND identity = ?")
            .bind(address)
            .bind(&identity)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn record_identity_change(
        &self,
        address: &str,
        identity_type: IdentityType,
        identity: &IdentityKey,
        verified: bool,
    ) -> Result<(), SqliteStoreError> {
        let identity_type = identity_type.as_str();
        query(
            "INSERT INTO client_identity_changes(address, identity, new_record, verified) \
             VALUES (?, ?, ?, ?) ON CONFLICT(address, identity) DO UPDATE SET \
             new_record = excluded.new_record, \
             verified = max(client_identity_changes.verified, excluded.verified)",
        )
        .bind(address)
        .bind(identity_type)
        .bind(identity.serialize())
        .bind(verified)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub(crate) async fn has_blocking_identity_change(
        &self,
        address: &str,
        identity_type: IdentityType,
    ) -> Result<bool, SqliteStoreError> {
        let count: i64 = query_scalar(
            "SELECT count(*) FROM client_identity_changes \
             WHERE address = ? AND identity = ? AND verified = true",
        )
        .bind(address)
        .bind(identity_type.as_str())
        .fetch_one(&self.db)
        .await?;
        Ok(count != 0)
    }

    pub(crate) async fn contact_is_verified(
        &self,
        address: &str,
    ) -> Result<bool, SqliteStoreError> {
        let Some(service_id) = ServiceId::parse_from_service_id_string(address) else {
            return Ok(false);
        };
        let verified: Option<bool> = query_scalar(
            "SELECT is_verified FROM contacts_verification_state \
             WHERE destination_aci = ? OR destination_aci = ?",
        )
        .bind(service_id.raw_uuid())
        .bind(address)
        .fetch_optional(&self.db)
        .await?
        .flatten();
        Ok(verified.unwrap_or(false))
    }
}
