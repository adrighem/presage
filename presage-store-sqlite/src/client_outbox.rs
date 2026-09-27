use sqlx::{Row, query};

use crate::{SqliteStore, SqliteStoreError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientOutboxKind {
    Direct,
    Group,
}

impl ClientOutboxKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Group => "group",
        }
    }

    fn parse(value: &str) -> Result<Self, SqliteStoreError> {
        match value {
            "direct" => Ok(Self::Direct),
            "group" => Ok(Self::Group),
            _ => Err(SqliteStoreError::InvalidFormat),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientOutboxMessage {
    pub id: i64,
    pub kind: ClientOutboxKind,
    pub recipient: String,
    pub body: String,
    pub timestamp: u64,
    pub attempts: u32,
}

impl SqliteStore {
    pub async fn initialize_client_outbox(&self) -> Result<(), SqliteStoreError> {
        query(
            "CREATE TABLE IF NOT EXISTS client_outbox (\
             id INTEGER PRIMARY KEY AUTOINCREMENT, \
             kind TEXT NOT NULL CHECK (kind IN ('direct', 'group')), \
             recipient TEXT NOT NULL, body TEXT NOT NULL, \
             timestamp INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, \
             next_attempt INTEGER NOT NULL DEFAULT 0)",
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub async fn enqueue_client_message(
        &self,
        kind: ClientOutboxKind,
        recipient: &str,
        body: &str,
        timestamp: u64,
    ) -> Result<i64, SqliteStoreError> {
        let timestamp = i64::try_from(timestamp).map_err(|_| SqliteStoreError::InvalidFormat)?;
        let result = query(
            "INSERT INTO client_outbox(kind, recipient, body, timestamp) VALUES (?, ?, ?, ?)",
        )
        .bind(kind.as_str())
        .bind(recipient)
        .bind(body)
        .bind(timestamp)
        .execute(&self.db)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn due_client_messages(
        &self,
        now: u64,
    ) -> Result<Vec<ClientOutboxMessage>, SqliteStoreError> {
        let now = i64::try_from(now).map_err(|_| SqliteStoreError::InvalidFormat)?;
        query(
            "SELECT id, kind, recipient, body, timestamp, attempts \
             FROM client_outbox WHERE next_attempt <= ? ORDER BY id",
        )
        .bind(now)
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .map(|row| {
            let timestamp: i64 = row.try_get("timestamp")?;
            let attempts: i64 = row.try_get("attempts")?;
            Ok(ClientOutboxMessage {
                id: row.try_get("id")?,
                kind: ClientOutboxKind::parse(row.try_get("kind")?)?,
                recipient: row.try_get("recipient")?,
                body: row.try_get("body")?,
                timestamp: timestamp
                    .try_into()
                    .map_err(|_| SqliteStoreError::InvalidFormat)?,
                attempts: attempts
                    .try_into()
                    .map_err(|_| SqliteStoreError::InvalidFormat)?,
            })
        })
        .collect()
    }

    pub async fn complete_client_message(&self, id: i64) -> Result<(), SqliteStoreError> {
        query("DELETE FROM client_outbox WHERE id = ?")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    pub async fn defer_client_message(
        &self,
        id: i64,
        attempts: u32,
        next_attempt: u64,
    ) -> Result<(), SqliteStoreError> {
        let next_attempt =
            i64::try_from(next_attempt).map_err(|_| SqliteStoreError::InvalidFormat)?;
        query("UPDATE client_outbox SET attempts = ?, next_attempt = ? WHERE id = ?")
            .bind(attempts)
            .bind(next_attempt)
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    pub async fn expedite_client_messages(&self, recipient: &str) -> Result<(), SqliteStoreError> {
        query("UPDATE client_outbox SET next_attempt = 0 WHERE recipient = ?")
            .bind(recipient)
            .execute(&self.db)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClientOutboxKind, OnNewIdentity, SqliteStore};

    #[tokio::test]
    async fn persists_and_schedules_client_outbox_messages()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::open(":memory:", OnNewIdentity::Reject).await?;
        store.initialize_client_outbox().await?;
        let id = store
            .enqueue_client_message(ClientOutboxKind::Direct, "recipient", "hello", 123)
            .await?;
        let due = store.due_client_messages(0).await?;
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].body, "hello");

        store.defer_client_message(id, 1, 500).await?;
        assert!(store.due_client_messages(499).await?.is_empty());
        assert_eq!(store.due_client_messages(500).await?[0].attempts, 1);
        store.expedite_client_messages("recipient").await?;
        assert_eq!(store.due_client_messages(0).await?.len(), 1);
        store.complete_client_message(id).await?;
        assert!(store.due_client_messages(u64::MAX / 2).await?.is_empty());
        Ok(())
    }
}
