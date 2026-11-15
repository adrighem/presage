use async_trait::async_trait;
use chrono::{DateTime, Utc};
use presage::{
    libsignal_service::{
        pre_keys::{KyberPreKeyStoreExt, PreKeysStore},
        prelude::{SessionStoreExt, Uuid},
        protocol::{
            CiphertextMessageType, DeviceId, Direction, GenericSignedPreKey, IdentityChange,
            IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord,
            KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, ProtocolStore,
            PublicKey, SenderKeyRecord, SenderKeyStore, ServiceId, SessionRecord, SessionStore,
            SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
        },
        push_service::DEFAULT_DEVICE_ID,
    },
    model::identity::OnNewIdentity,
    store::StateStore,
};
use std::sync::{Arc, Mutex};

use sqlx::{query, query_scalar};
use tracing::warn;

use crate::{SqliteStore, SqliteStoreError, error::SqlxErrorExt};

#[derive(Clone)]
pub struct SqliteProtocolStore {
    pub(crate) store: SqliteStore,
    pub(crate) identity: IdentityType,
    /// Pre-key uses that `store_session` commits with the session, so a failed session write
    /// keeps the pre-key for the redelivered message. Shared because libsignal-service passes a
    /// clone of the store per store trait.
    pending_pre_key_uses: Arc<Mutex<PendingPreKeyUses>>,
}

#[derive(Default)]
struct PendingPreKeyUses {
    pre_keys: Vec<u32>,
    one_time_kyber_pre_keys: Vec<u32>,
    last_resort_kyber_base_keys: Vec<LastResortKyberBaseKey>,
}

#[derive(PartialEq, Eq)]
struct LastResortKyberBaseKey {
    kyber_pre_key_id: u32,
    signed_pre_key_id: u32,
    base_key: Box<[u8]>,
}

fn reused_base_key() -> SignalProtocolError {
    SignalProtocolError::InvalidMessage(CiphertextMessageType::PreKey, "reused base key".to_owned())
}

#[derive(Debug, Clone, Copy, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum IdentityType {
    Aci,
    Pni,
}

impl IdentityType {
    pub(crate) fn identity_key_pair_key(&self) -> &'static str {
        match self {
            Self::Aci => "identity_keypair_aci",
            Self::Pni => "identity_keypair_pni",
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Aci => "aci",
            Self::Pni => "pni",
        }
    }
}

impl SqliteProtocolStore {
    pub(crate) fn new(store: SqliteStore, identity: IdentityType) -> Self {
        Self {
            store,
            identity,
            pending_pre_key_uses: Default::default(),
        }
    }

    fn pending_pre_key_uses(&self) -> std::sync::MutexGuard<'_, PendingPreKeyUses> {
        // Never held across an await or panic point, so a poisoned queue is still consistent.
        self.pending_pre_key_uses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn apply_pre_key_uses(
        &self,
        transaction: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
        uses: &PendingPreKeyUses,
    ) -> Result<(), SignalProtocolError> {
        for id in &uses.pre_keys {
            sqlx::query("DELETE FROM pre_keys WHERE id = ? AND identity = ?")
                .bind(id)
                .bind(self.identity)
                .execute(&mut **transaction)
                .await
                .into_protocol_error()?;
        }
        for id in &uses.one_time_kyber_pre_keys {
            sqlx::query(
                "DELETE FROM kyber_pre_keys WHERE id = ? AND identity = ? AND is_last_resort = FALSE",
            )
            .bind(id)
            .bind(self.identity)
            .execute(&mut **transaction)
            .await
            .into_protocol_error()?;
        }
        for seen in &uses.last_resort_kyber_base_keys {
            let result = sqlx::query(
                "INSERT INTO base_keys_seen (kyber_pre_key_id, signed_pre_key_id, identity, base_key)
                VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(seen.kyber_pre_key_id)
            .bind(seen.signed_pre_key_id)
            .bind(self.identity)
            .bind(&*seen.base_key)
            .execute(&mut **transaction)
            .await;
            if matches!(result, Err(sqlx::Error::Database(ref e)) if e.kind() == sqlx::error::ErrorKind::UniqueViolation)
            {
                return Err(reused_base_key());
            }
            result.into_protocol_error()?;
        }
        Ok(())
    }
}

impl ProtocolStore for SqliteProtocolStore {}

#[async_trait(?Send)]
impl SessionStore for SqliteProtocolStore {
    /// Look up the session corresponding to `address`.
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let device_id: u8 = address.device_id().into();
        let address = address.name();
        query!(
            "SELECT record FROM sessions
            WHERE address = ? AND device_id = ? AND identity = ?",
            address,
            device_id,
            self.identity,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|record| SessionRecord::deserialize(&record.record))
        .transpose()
    }

    /// Set the entry for `address` to the value of `record`, committing queued pre-key uses with
    /// it. On failure the uses are dropped and the pre-keys stay.
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let device_id: u8 = address.device_id().into();
        let address = address.name();
        let record = record.serialize()?;
        let pre_key_uses = std::mem::take(&mut *self.pending_pre_key_uses());

        let mut transaction = self.store.begin_write().await.into_protocol_error()?;

        // Note: It is faster to do the update in a separate query and only insert the record if
        // the update did not do anything.
        let res = query!(
            "UPDATE sessions SET record = ?4
            WHERE address = ?1 AND device_id = ?2 AND identity = ?3",
            address,
            device_id,
            self.identity,
            record,
        )
        .execute(&mut *transaction)
        .await
        .into_protocol_error()?;

        if res.rows_affected() == 0 {
            query!(
                "INSERT INTO sessions (address, device_id, identity, record)
                VALUES (?1, ?2, ?3, ?4)",
                address,
                device_id,
                self.identity,
                record,
            )
            .execute(&mut *transaction)
            .await
            .into_protocol_error()?;
        }

        self.apply_pre_key_uses(&mut transaction, &pre_key_uses)
            .await?;

        transaction.commit().await.into_protocol_error()?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStoreExt for SqliteProtocolStore {
    /// Get the IDs of all known sub devices with active sessions for a recipient.
    ///
    /// This should return every device except for the main device [DEFAULT_DEVICE_ID].
    async fn get_sub_device_sessions(
        &self,
        name: &ServiceId,
    ) -> Result<Vec<DeviceId>, SignalProtocolError> {
        let address = name.service_id_string();
        let device_id: u8 = (*DEFAULT_DEVICE_ID).into();
        query_scalar!(
            "SELECT device_id AS 'id: u32' FROM sessions
            WHERE address = ? AND device_id != ? AND identity = ?",
            address,
            device_id,
            self.identity,
        )
        .fetch_all(&self.store.db)
        .await
        .map(|device_ids| {
            device_ids
                .into_iter()
                .filter_map(|device_id| device_id.try_into().ok())
                .collect()
        })
        .into_protocol_error()
    }

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        let device_id: u8 = address.device_id().into();
        let address = address.name();
        query!(
            "DELETE FROM sessions WHERE address = ? AND device_id = ? AND identity = ?",
            address,
            device_id,
            self.identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Remove the session records corresponding to all devices of a recipient
    /// ID.
    ///
    /// Returns the number of deleted sessions.
    async fn delete_all_sessions(&self, name: &ServiceId) -> Result<usize, SignalProtocolError> {
        let address = name.service_id_string();
        let res = query!(
            "DELETE FROM sessions WHERE address = ? AND identity = ?",
            address,
            self.identity
        )
        .execute(&self.store.db)
        .await
        .map_err(SqliteStoreError::from)?;
        Ok(res.rows_affected().try_into().expect("usize overflow"))
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqliteProtocolStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let record = query_scalar!(
            "SELECT record FROM pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        PreKeyRecord::deserialize(&record)
    }

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO pre_keys (id, identity, record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT DO UPDATE SET record = ?3",
            id,
            self.identity,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Remove the entry for `prekey_id` once the next `store_session` commits.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.pending_pre_key_uses().pre_keys.push(prekey_id.into());
        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeysStore for SqliteProtocolStore {
    /// ID of the next pre key
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let max_id = query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM pre_keys WHERE identity = ?",
            self.identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(max_id.map(|id| id + 1).unwrap_or(1))
    }

    /// ID of the next signed pre key
    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let max_id = query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM signed_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(max_id.map(|id| id + 1).unwrap_or(1))
    }

    /// ID of the next PQ pre key
    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let max_id = query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM kyber_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(max_id.map(|id| id + 1).unwrap_or(1))
    }

    /// number of signed pre-keys we currently have in store
    async fn signed_pre_keys_count(&self) -> Result<usize, SignalProtocolError> {
        query_scalar!(
            "SELECT COUNT(id) FROM signed_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|count| count.try_into().expect("invalid usize"))
    }

    /// number of kyber pre-keys we currently have in store
    async fn kyber_pre_keys_count(&self, last_resort: bool) -> Result<usize, SignalProtocolError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(id) FROM kyber_pre_keys WHERE identity = ? AND is_last_resort = ?",
        )
        .bind(self.identity)
        .bind(last_resort)
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|count| count.try_into().expect("invalid usize"))
    }

    async fn signed_prekey_id(&self) -> Result<Option<SignedPreKeyId>, SignalProtocolError> {
        query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM signed_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|id| id.map(From::from))
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> Result<Option<KyberPreKeyId>, SignalProtocolError> {
        query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM kyber_pre_keys
            WHERE identity = ? AND is_last_resort = TRUE",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|id| id.map(From::from))
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteProtocolStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let bytes = query_scalar!(
            "SELECT record FROM signed_pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity,
        )
        .fetch_one(&self.store.db)
        .await
        .map_err(SqliteStoreError::from)?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let bytes = record.serialize()?;
        query!(
            "INSERT INTO signed_pre_keys (id, identity, record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT DO UPDATE SET record = ?3",
            id,
            self.identity,
            bytes,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqliteProtocolStore {
    /// Look up the signed kyber pre-key corresponding to `kyber_prekey_id`.
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let bytes = query_scalar!(
            "SELECT record FROM kyber_pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    /// Set the entry for `kyber_prekey_id` to the value of `record`.
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO kyber_pre_keys (id, identity, record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT DO UPDATE SET record = ?3",
            id,
            self.identity,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Mark the entry for `kyber_prekey_id` as "used".
    ///
    /// This means different things for one-time and last-resort Kyber keys.
    /// See the [trait documentation](https://github.com/signalapp/libsignal/blob/eb616f63ed053af83e577f36169f5cb5889bb904/rust/protocol/src/storage/traits.rs#L129), [reference implementation](https://github.com/signalapp/libsignal/blob/eb616f63ed053af83e577f36169f5cb5889bb904/rust/protocol/src/storage/inmem.rs#L247) (and the [comment for it](https://github.com/signalapp/libsignal/blob/eb616f63ed053af83e577f36169f5cb5889bb904/rust/protocol/src/storage/inmem.rs#L196)).
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let kyber_prekey_id: u32 = kyber_prekey_id.into();

        let is_last_resort = query_scalar!(
            "SELECT is_last_resort FROM kyber_pre_keys WHERE id = ? and identity = ?",
            kyber_prekey_id,
            self.identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?
            != 0;

        if !is_last_resort {
            // Delete only one-time (i.e. non-last-resort) pre keys.
            self.pending_pre_key_uses()
                .one_time_kyber_pre_keys
                .push(kyber_prekey_id);
            return Ok(());
        }

        // Mark last-resort keys as used in base_keys_seen. Reject a base key already committed
        // or queued.
        let seen = LastResortKyberBaseKey {
            kyber_pre_key_id: kyber_prekey_id,
            signed_pre_key_id: ec_prekey_id.into(),
            base_key: base_key.serialize(),
        };
        let committed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM base_keys_seen
            WHERE kyber_pre_key_id = ? AND signed_pre_key_id = ? AND identity = ? AND base_key = ?)",
        )
        .bind(seen.kyber_pre_key_id)
        .bind(seen.signed_pre_key_id)
        .bind(self.identity)
        .bind(&*seen.base_key)
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;

        let mut pending = self.pending_pre_key_uses();
        if committed || pending.last_resort_kyber_base_keys.contains(&seen) {
            return Err(reused_base_key());
        }
        pending.last_resort_kyber_base_keys.push(seen);
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for SqliteProtocolStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO kyber_pre_keys
            (id, identity, is_last_resort, record)
            VALUES (?1, ?2, TRUE, ?3)
            ON CONFLICT DO UPDATE SET is_last_resort = TRUE, record = ?3",
            id,
            self.identity,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError> {
        query_scalar!(
            "SELECT record FROM kyber_pre_keys
            WHERE identity = ? AND is_last_resort = TRUE",
            self.identity,
        )
        .fetch_all(&self.store.db)
        .await
        .into_protocol_error()?
        .into_iter()
        .map(|record| KyberPreKeyRecord::deserialize(&record))
        .collect()
    }

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        query!(
            "DELETE FROM kyber_pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Analogous to markAllOneTimeKyberPreKeysStaleIfNecessary
    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _stale_time: DateTime<Utc>,
    ) -> Result<(), SignalProtocolError> {
        unimplemented!("should not be used yet")
    }

    /// Analogue of deleteAllStaleOneTimeKyberPreKeys
    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _threshold: DateTime<Utc>,
        _min_count: usize,
    ) -> Result<(), SignalProtocolError> {
        unimplemented!("should not be used yet")
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteProtocolStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let key = self.identity.identity_key_pair_key();
        let bytes = query_scalar!("SELECT value FROM kv WHERE key = ?", key)
            .fetch_one(&self.store.db)
            .await
            .into_protocol_error()?;
        IdentityKeyPair::try_from(&*bytes)
    }

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// may be the same, but the store registration id returned by this method should
    /// be regenerated.
    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let data = self.store.load_registration_data().await?.ok_or_else(|| {
            SignalProtocolError::InvalidState(
                "failed to load registration ID",
                "no registration data".into(),
            )
        })?;
        Ok(data.registration_id)
    }

    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced (`Ok(true)`). If it is
    /// new or hasn't changed, the return value should be `Ok(false)`.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let address = address.name();
        let bytes = identity.serialize();

        let mut tx = self.store.begin_write().await.into_protocol_error()?;

        // Note: It is faster to do the update in a separate query and only insert the record if
        // the update did not do anything.
        let is_replaced = query!(
            "UPDATE identities SET record = ?3
            WHERE address = ?1 AND identity = ?2",
            address,
            self.identity,
            bytes,
        )
        .execute(&mut *tx)
        .await
        .into_protocol_error()?
        .rows_affected()
            != 0;

        if !is_replaced {
            query!(
                "INSERT INTO identities (address, identity, record)
                VALUES (?1, ?2, ?3)",
                address,
                self.identity,
                bytes,
            )
            .execute(&mut *tx)
            .await
            .into_protocol_error()?;
        }

        tx.commit().await.into_protocol_error()?;

        Ok(if is_replaced {
            IdentityChange::ReplacedExisting
        } else {
            IdentityChange::NewOrUnchanged
        })
    }

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        if matches!(
            self.store.trust_new_identities,
            OnNewIdentity::TrustUnverified
        ) && matches!(direction, Direction::Sending)
            && self
                .store
                .has_blocking_identity_change(address.name(), self.identity)
                .await?
        {
            return Ok(false);
        }

        if let Some(trusted_key) = self.get_identity(address).await? {
            // when we encounter some identity we know, we need to decide whether we trust it or not
            if identity == &trusted_key {
                Ok(true)
            } else {
                match self.store.trust_new_identities {
                    OnNewIdentity::Trust => Ok(true),
                    OnNewIdentity::Reject => Ok(false),
                    OnNewIdentity::TrustUnverified => {
                        let verified = self.store.contact_is_verified(address.name()).await?;
                        self.store
                            .record_identity_change(
                                address.name(),
                                self.identity,
                                identity,
                                verified,
                            )
                            .await?;
                        Ok(matches!(direction, Direction::Receiving) || !verified)
                    }
                }
            }
        } else {
            // when we encounter a new identity, we trust it by default
            warn!(%address, "trusting new identity");
            Ok(true)
        }
    }

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let address = address.name();
        query_scalar!(
            "SELECT record FROM identities
            WHERE address = ? AND identity = ?",
            address,
            self.identity,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|bytes| IdentityKey::decode(&bytes))
        .transpose()
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for SqliteProtocolStore {
    /// Assign `record` to the entry for `(sender, distribution_id)`.
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let address = sender.name();
        let device_id: u8 = sender.device_id().into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO sender_keys
            (address, device_id, identity, distribution_id, record)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT DO UPDATE SET record = ?5",
            address,
            device_id,
            self.identity,
            distribution_id,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Look up the entry corresponding to `(sender, distribution_id)`.
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let address = sender.name();
        let device_id: u8 = sender.device_id().into();
        query_scalar!(
            "SELECT record FROM sender_keys
            WHERE address = ? AND device_id = ? AND identity = ? AND distribution_id = ?",
            address,
            device_id,
            self.identity,
            distribution_id,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|record| SenderKeyRecord::deserialize(&record))
        .transpose()
    }
}

#[cfg(test)]
mod test {
    use std::time::SystemTime;

    use presage::{
        libsignal_service::{
            proto::{Verified, verified},
            protocol::{
                CiphertextMessage, DeviceId, Direction, IdentityKey, IdentityKeyStore,
                InMemIdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyStore,
                PreKeyBundle, PreKeySignalMessage, ProtocolAddress, Timestamp, kem,
                message_decrypt_prekey, message_encrypt, process_prekey_bundle,
            },
            push_service::ServiceError,
        },
        model::contacts::Contact,
        store::{ContentsStore, TransientStoreError},
    };
    use sqlx::sqlite::SqliteConnectOptions;

    use super::*;

    #[tokio::test]
    async fn blocks_verified_identity_changes_until_acceptance()
    -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::TrustUnverified).await?;
        sqlite_store.initialize_identity_change_tracking().await?;
        let contact_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001")?;
        let address = contact_uuid.to_string();
        let protocol_address = ProtocolAddress::new(address.clone(), DeviceId::new(1)?);
        let first = IdentityKey::new(KeyPair::generate(&mut rand::rng()).public_key);
        let replacement = IdentityKey::new(KeyPair::generate(&mut rand::rng()).public_key);
        let mut contact_store = sqlite_store.clone();
        contact_store
            .save_contact(&Contact {
                uuid: contact_uuid,
                phone_number: None,
                name: "Test Contact".into(),
                verified: Verified {
                    destination_aci: Some(address.clone()),
                    destination_aci_binary: None,
                    identity_key: Some(first.serialize().to_vec()),
                    state: Some(verified::State::Verified.into()),
                    null_message: None,
                },
                profile_key: Vec::new(),
                expire_timer: 0,
                expire_timer_version: 2,
                inbox_position: 0,
                avatar: None,
            })
            .await?;
        let mut protocol_store = SqliteProtocolStore::new(sqlite_store.clone(), IdentityType::Aci);
        protocol_store
            .save_identity(&protocol_address, &first)
            .await?;

        assert!(
            !protocol_store
                .is_trusted_identity(&protocol_address, &replacement, Direction::Sending)
                .await?
        );
        assert!(
            protocol_store
                .is_trusted_identity(&protocol_address, &replacement, Direction::Receiving)
                .await?
        );
        protocol_store
            .save_identity(&protocol_address, &replacement)
            .await?;
        assert!(
            !protocol_store
                .is_trusted_identity(&protocol_address, &replacement, Direction::Sending)
                .await?
        );
        assert_eq!(
            sqlite_store.identity_change_notices().await?,
            vec![crate::IdentityChangeNotice {
                address: address.clone(),
                verified: true,
            }]
        );

        assert!(sqlite_store.accept_identity_change(&address).await?);
        assert!(
            protocol_store
                .is_trusted_identity(&protocol_address, &replacement, Direction::Sending)
                .await?
        );
        assert!(sqlite_store.identity_change_notices().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn trusts_unverified_identity_changes_with_dismissible_notice()
    -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::TrustUnverified).await?;
        sqlite_store.initialize_identity_change_tracking().await?;
        let address = "00000000-0000-0000-0000-000000000002".to_owned();
        let protocol_address = ProtocolAddress::new(address.clone(), DeviceId::new(1)?);
        let first = IdentityKey::new(KeyPair::generate(&mut rand::rng()).public_key);
        let replacement = IdentityKey::new(KeyPair::generate(&mut rand::rng()).public_key);
        let mut protocol_store = SqliteProtocolStore::new(sqlite_store.clone(), IdentityType::Aci);
        protocol_store
            .save_identity(&protocol_address, &first)
            .await?;

        assert!(
            protocol_store
                .is_trusted_identity(&protocol_address, &replacement, Direction::Sending)
                .await?
        );
        assert_eq!(
            sqlite_store.identity_change_notices().await?,
            vec![crate::IdentityChangeNotice {
                address: address.clone(),
                verified: false,
            }]
        );
        sqlite_store.dismiss_identity_change(&address).await?;
        assert!(sqlite_store.identity_change_notices().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn kyber_pre_keys_mark_used_one_time() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut protocol_store = SqliteProtocolStore::new(sqlite_store, IdentityType::Aci);

        let id = KyberPreKeyId::from(0);
        let keypair = KeyPair::generate(&mut rand::rng());
        let record = KyberPreKeyRecord::generate(
            presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
            id,
            &keypair.private_key,
        )?;
        let ec_prekey_id = SignedPreKeyId::from(1);

        protocol_store.save_kyber_pre_key(id, &record).await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        protocol_store
            .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        protocol_store
            .store_session(&test_address()?, &SessionRecord::new_fresh())
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn kyber_pre_keys_mark_used_last_resort() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rand::rng();
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut protocol_store = SqliteProtocolStore::new(sqlite_store, IdentityType::Aci);

        let id = KyberPreKeyId::from(0);
        let keypair = KeyPair::generate(&mut rand::rng());

        // Signed pre key
        let ec_pre_key_pair = KeyPair::generate(&mut rng);
        let ec_pre_key_signature = keypair
            .private_key
            .calculate_signature(&ec_pre_key_pair.public_key.serialize(), &mut rng)?;
        let ec_prekey_id = SignedPreKeyId::from(1);
        let ec_prekey_record = SignedPreKeyRecord::new(
            ec_prekey_id,
            Timestamp::from_epoch_millis(1760968452908),
            &ec_pre_key_pair,
            &ec_pre_key_signature,
        );

        // Kyber pre key
        let kyber_pre_key_record = KyberPreKeyRecord::generate(
            presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
            id,
            &keypair.private_key,
        )?;

        protocol_store
            .save_signed_pre_key(ec_prekey_id, &ec_prekey_record)
            .await?;

        protocol_store
            .store_last_resort_kyber_pre_key(id, &kyber_pre_key_record)
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        protocol_store
            .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        // A reused base key is rejected while its first use is still queued...
        assert!(
            protocol_store
                .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
                .await
                .is_err()
        );
        protocol_store
            .store_session(&test_address()?, &SessionRecord::new_fresh())
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        // ...and once it is committed.
        assert!(
            protocol_store
                .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
                .await
                .is_err()
        );

        Ok(())
    }

    fn test_address() -> Result<ProtocolAddress, Box<dyn std::error::Error>> {
        Ok(ProtocolAddress::new(
            "00000000-0000-0000-0000-000000000003".to_owned(),
            DeviceId::new(1)?,
        ))
    }

    async fn saved_pre_key(
        protocol_store: &mut SqliteProtocolStore,
    ) -> Result<PreKeyId, Box<dyn std::error::Error>> {
        let id = PreKeyId::from(7);
        let record = PreKeyRecord::new(id, &KeyPair::generate(&mut rand::rng()));
        protocol_store.save_pre_key(id, &record).await?;
        Ok(id)
    }

    #[tokio::test]
    async fn pre_key_removal_waits_for_session() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut protocol_store = SqliteProtocolStore::new(sqlite_store, IdentityType::Aci);
        let id = saved_pre_key(&mut protocol_store).await?;

        // libsignal hands each store trait its own clone.
        protocol_store.clone().remove_pre_key(id).await?;
        assert!(protocol_store.get_pre_key(id).await.is_ok());

        protocol_store
            .clone()
            .store_session(&test_address()?, &SessionRecord::new_fresh())
            .await?;
        assert!(protocol_store.get_pre_key(id).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn failed_session_store_keeps_pre_key() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut protocol_store = SqliteProtocolStore::new(sqlite_store.clone(), IdentityType::Aci);
        let id = saved_pre_key(&mut protocol_store).await?;
        sqlx::query(
            "CREATE TRIGGER fail_session_insert BEFORE INSERT ON sessions
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
        )
        .execute(&sqlite_store.db)
        .await?;

        protocol_store.remove_pre_key(id).await?;
        assert!(
            protocol_store
                .store_session(&test_address()?, &SessionRecord::new_fresh())
                .await
                .is_err()
        );
        assert!(protocol_store.get_pre_key(id).await.is_ok());

        // The failed attempt dropped its queued removal.
        sqlx::query("DROP TRIGGER fail_session_insert")
            .execute(&sqlite_store.db)
            .await?;
        protocol_store
            .store_session(&test_address()?, &SessionRecord::new_fresh())
            .await?;
        assert!(protocol_store.get_pre_key(id).await.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn sessions_by_service_id() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut protocol_store = SqliteProtocolStore::new(sqlite_store, IdentityType::Aci);

        let uuid = Uuid::from_u128(1);
        let aci: ServiceId = presage::libsignal_service::protocol::Aci::from(uuid).into();
        let pni: ServiceId = presage::libsignal_service::protocol::Pni::from(uuid).into();
        let record = SessionRecord::new_fresh();

        for (service_id, device_id) in [(aci, 1), (aci, 2), (pni, 1), (pni, 3)] {
            let address =
                ProtocolAddress::new(service_id.service_id_string(), device_id.try_into()?);
            protocol_store.store_session(&address, &record).await?;
        }

        assert_eq!(
            protocol_store.get_sub_device_sessions(&aci).await?,
            vec![2.try_into()?]
        );
        assert_eq!(
            protocol_store.get_sub_device_sessions(&pni).await?,
            vec![3.try_into()?]
        );

        assert_eq!(protocol_store.delete_all_sessions(&aci).await?, 2);
        assert!(
            protocol_store
                .get_sub_device_sessions(&aci)
                .await?
                .is_empty()
        );
        assert_eq!(protocol_store.delete_all_sessions(&pni).await?, 2);

        Ok(())
    }

    /// Bob, whose sessions and pre-keys live in a [`SqliteProtocolStore`], and a pre-key message
    /// from Alice that consumes his one-time EC and Kyber pre-keys.
    struct PreKeyMessageFixture {
        bob_store: SqliteProtocolStore,
        bob_identity_store: InMemIdentityKeyStore,
        bob_address: ProtocolAddress,
        alice_address: ProtocolAddress,
        message: PreKeySignalMessage,
        pre_key_id: PreKeyId,
        kyber_pre_key_id: KyberPreKeyId,
    }

    impl PreKeyMessageFixture {
        async fn new(sqlite_store: SqliteStore) -> Result<Self, Box<dyn std::error::Error>> {
            let mut rng = rand::rng();
            let bob_store = SqliteProtocolStore::new(sqlite_store, IdentityType::Aci);
            let bob_identity = IdentityKeyPair::generate(&mut rng);
            let bob_address = ProtocolAddress::new("bob".to_owned(), DeviceId::new(1)?);
            let alice_address = ProtocolAddress::new("alice".to_owned(), DeviceId::new(1)?);

            let pre_key_id = PreKeyId::from(7);
            let pre_key_pair = KeyPair::generate(&mut rng);
            bob_store
                .clone()
                .save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair))
                .await?;

            let signed_pre_key_id = SignedPreKeyId::from(1);
            let signed_pre_key_pair = KeyPair::generate(&mut rng);
            let signed_pre_key_signature = bob_identity
                .private_key()
                .calculate_signature(&signed_pre_key_pair.public_key.serialize(), &mut rng)?;
            bob_store
                .clone()
                .save_signed_pre_key(
                    signed_pre_key_id,
                    &SignedPreKeyRecord::new(
                        signed_pre_key_id,
                        Timestamp::from_epoch_millis(0),
                        &signed_pre_key_pair,
                        &signed_pre_key_signature,
                    ),
                )
                .await?;

            let kyber_pre_key_id = KyberPreKeyId::from(1);
            let kyber_pre_key = KyberPreKeyRecord::generate(
                kem::KeyType::Kyber1024,
                kyber_pre_key_id,
                bob_identity.private_key(),
            )?;
            bob_store
                .clone()
                .save_kyber_pre_key(kyber_pre_key_id, &kyber_pre_key)
                .await?;

            let bundle = PreKeyBundle::new(
                2,
                DeviceId::new(1)?,
                Some((pre_key_id, pre_key_pair.public_key)),
                signed_pre_key_id,
                signed_pre_key_pair.public_key,
                signed_pre_key_signature.to_vec(),
                kyber_pre_key_id,
                kyber_pre_key.public_key()?,
                kyber_pre_key.signature()?,
                *bob_identity.identity_key(),
            )?;

            let mut alice = InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), 1)?;
            process_prekey_bundle(
                &bob_address,
                &alice_address,
                &mut alice.session_store,
                &mut alice.identity_store,
                &bundle,
                SystemTime::now(),
                &mut rng,
            )
            .await?;
            let CiphertextMessage::PreKeySignalMessage(message) = message_encrypt(
                b"hello bob",
                &bob_address,
                &alice_address,
                &mut alice.session_store,
                &mut alice.identity_store,
                SystemTime::now(),
                &mut rng,
            )
            .await?
            else {
                return Err("expected a pre-key message".into());
            };

            Ok(Self {
                bob_store,
                bob_identity_store: InMemIdentityKeyStore::new(bob_identity, 2),
                bob_address,
                alice_address,
                message,
                pre_key_id,
                kyber_pre_key_id,
            })
        }

        /// Decrypts the message the way libsignal-service does: a separate store clone per
        /// store argument.
        async fn decrypt(&mut self) -> Result<Vec<u8>, SignalProtocolError> {
            message_decrypt_prekey(
                &self.message,
                &self.alice_address,
                &self.bob_address,
                &mut self.bob_store.clone(),
                &mut self.bob_identity_store,
                &mut self.bob_store.clone(),
                &self.bob_store.clone(),
                &mut self.bob_store.clone(),
                &mut rand::rng(),
            )
            .await
        }

        /// Whether the one-time EC and Kyber pre-keys are still stored.
        async fn pre_keys_present(&self) -> (bool, bool) {
            (
                self.bob_store.get_pre_key(self.pre_key_id).await.is_ok(),
                self.bob_store
                    .get_kyber_pre_key(self.kyber_pre_key_id)
                    .await
                    .is_ok(),
            )
        }
    }

    #[tokio::test]
    async fn redelivered_pre_key_message_decrypts_after_failed_session_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut fixture = PreKeyMessageFixture::new(sqlite_store.clone()).await?;
        sqlx::query(
            "CREATE TRIGGER fail_session_insert BEFORE INSERT ON sessions
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
        )
        .execute(&sqlite_store.db)
        .await?;

        assert!(fixture.decrypt().await.is_err());
        assert_eq!(fixture.pre_keys_present().await, (true, true));

        sqlx::query("DROP TRIGGER fail_session_insert")
            .execute(&sqlite_store.db)
            .await?;
        assert_eq!(fixture.decrypt().await?, b"hello bob");
        assert_eq!(fixture.pre_keys_present().await, (false, false));
        assert!(
            fixture
                .bob_store
                .load_session(&fixture.alice_address)
                .await?
                .is_some()
        );

        Ok(())
    }

    #[tokio::test]
    async fn write_lock_contention_is_transient_and_keeps_pre_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "presage-store-contention-{}.db3",
            rand::random::<u64>()
        ));
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_millis(20));
        let sqlite_store = SqliteStore::open_with_options(options, OnNewIdentity::Trust).await?;
        let mut fixture = PreKeyMessageFixture::new(sqlite_store.clone()).await?;

        // Another connection holds the write lock.
        let other =
            SqliteStore::open(path.to_str().ok_or("non UTF-8 path")?, OnNewIdentity::Trust).await?;
        let lock = other.begin_write().await?;

        let error = fixture.decrypt().await.unwrap_err();
        assert!(
            TransientStoreError::is_cause_of(&ServiceError::from(error)),
            "write lock contention must reach the receive loop as transient"
        );
        assert_eq!(fixture.pre_keys_present().await, (true, true));

        lock.rollback().await?;
        assert_eq!(fixture.decrypt().await?, b"hello bob");
        assert_eq!(fixture.pre_keys_present().await, (false, false));

        other.close().await;
        sqlite_store.close().await;
        for suffix in ["", "-shm", "-wal"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        Ok(())
    }
}
