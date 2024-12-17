use chrono::DateTime;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::SqlitePool;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub public_key: String, // hex
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct TeamUser {
    pub user_public_key: String, // hex
    pub team_id: u32,
    pub role: TeamUserRole,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum TeamUserRole {
    Admin,
    Member,
}

impl User {
    pub async fn is_team_admin(
        pool: &SqlitePool,
        pubkey: &PublicKey,
        team_id: u32,
    ) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) FROM team_users WHERE user_public_key = ?1 AND team_id = ?2 AND role = 'admin'";
        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(pubkey.to_hex())
            .bind(team_id)
            .fetch_one(pool)
            .await?;
        Ok(count > 0)
    }

    #[allow(dead_code)]
    pub async fn is_team_member(
        pool: &SqlitePool,
        pubkey: &PublicKey,
        team_id: u32,
    ) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) FROM team_users WHERE user_public_key = ?1 AND team_id = ?2 AND role = 'member'";
        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(pubkey.to_hex())
            .bind(team_id)
            .fetch_one(pool)
            .await?;
        Ok(count > 0)
    }

    #[allow(dead_code)]
    pub async fn is_team_teammate(
        pool: &SqlitePool,
        pubkey: &PublicKey,
        team_id: u32,
    ) -> Result<bool, UserError> {
        let query = "SELECT COUNT(*) FROM team_users WHERE user_public_key = ?1 AND team_id = ?2";
        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(pubkey.to_hex())
            .bind(team_id)
            .fetch_one(pool)
            .await?;
        Ok(count > 0)
    }
}
