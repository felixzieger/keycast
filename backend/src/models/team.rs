use crate::encryption::{file_key_manager::FileKeyManager, EncryptionError, KeyManager};
use crate::models::stored_key::StoredKey;
use crate::models::user::{TeamUser, TeamUserRole, User, UserError};
use chrono::DateTime;
use nostr_sdk::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::SqlitePool;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TeamError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("User is not authorized to perform this action")]
    NotAuthorized,

    #[error("User is not an admin of the team")]
    NotAdmin(#[from] UserError),

    #[error("User is already a member of the team")]
    UserAlreadyMember,

    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Team {
    pub id: u32,
    pub name: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamWithRelations {
    pub team: Team,
    pub team_users: Vec<TeamUser>, // Use team_user here so we get the role
    pub stored_keys: Vec<StoredKey>,
}

impl Team {
    pub async fn for_user(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
    ) -> Result<Vec<TeamWithRelations>, TeamError> {
        let teams = sqlx::query_as::<_, Team>(
            "SELECT * FROM teams WHERE id IN (SELECT team_id FROM team_users WHERE user_public_key = ?1)",
        )
        .bind(user_pubkey.to_hex())
        .fetch_all(pool)
        .await?;

        let mut teams_with_relations = Vec::new();

        for team in teams {
            // Get team_users for this team
            let team_users = sqlx::query_as::<_, TeamUser>(
                r#"
                SELECT tu.* 
                FROM team_users tu
                WHERE tu.team_id = ?1
                "#,
            )
            .bind(team.id)
            .fetch_all(pool)
            .await?;

            // Get stored keys for this team
            let stored_keys =
                sqlx::query_as::<_, StoredKey>("SELECT * FROM stored_keys WHERE team_id = ?1")
                    .bind(team.id)
                    .fetch_all(pool)
                    .await?;

            teams_with_relations.push(TeamWithRelations {
                team,
                team_users,
                stored_keys,
            });
        }

        Ok(teams_with_relations)
    }

    pub async fn get(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
    ) -> Result<TeamWithRelations, TeamError> {
        // Verify admin status before updating
        if !User::is_team_admin(pool, user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        // Get team
        let team = sqlx::query_as::<_, Team>("SELECT * FROM teams WHERE id = ?1")
            .bind(team_id)
            .fetch_one(pool)
            .await?;

        // Get team_users for this team
        let team_users = sqlx::query_as::<_, TeamUser>(
            r#"
            SELECT tu.* 
            FROM team_users tu
            WHERE tu.team_id = ?1
            "#,
        )
        .bind(team_id)
        .fetch_all(pool)
        .await?;

        // Get stored keys for this team
        let stored_keys =
            sqlx::query_as::<_, StoredKey>("SELECT * FROM stored_keys WHERE team_id = ?1")
                .bind(team_id)
                .fetch_all(pool)
                .await?;

        Ok(TeamWithRelations {
            team,
            team_users,
            stored_keys,
        })
    }

    pub async fn create(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        name: &str,
    ) -> Result<TeamWithRelations, TeamError> {
        let mut tx = pool.begin().await?;

        // First, try to insert the user if they don't exist
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO users (public_key, created_at, updated_at)
            VALUES (?1, datetime('now'), datetime('now'))
            "#,
        )
        .bind(user_pubkey.to_hex())
        .execute(&mut *tx)
        .await?;

        // Then, insert the team
        let team = sqlx::query_as::<_, Team>(
            r#"
            INSERT INTO teams (name, created_at, updated_at)
            VALUES (?1, datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to insert team: {}", e);
            TeamError::from(e)
        })?;

        // Finally, create the team_user relationship with admin role
        let team_user = sqlx::query_as::<_, TeamUser>(
            r#"
            INSERT INTO team_users (team_id, user_public_key, role, created_at, updated_at)
            VALUES (?1, ?2, 'admin', datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(team.id)
        .bind(user_pubkey.to_hex())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to insert team_user: {}", e);
            TeamError::from(e)
        })?;

        // Commit the transaction
        tx.commit().await.map_err(|e| {
            tracing::error!("Failed to commit transaction: {}", e);
            TeamError::from(e)
        })?;

        Ok(TeamWithRelations {
            team,
            team_users: vec![team_user],
            stored_keys: vec![],
        })
    }

    pub async fn update(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
        name: &str,
    ) -> Result<Team, TeamError> {
        let mut tx = pool.begin().await?;

        // Verify admin status before updating
        if !User::is_team_admin(pool, user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        let team = sqlx::query_as::<_, Team>(
            r#"
            UPDATE teams SET name = ?1 WHERE id = ?2
            RETURNING *
            "#,
        )
        .bind(name)
        .bind(team_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(team)
    }

    pub async fn delete(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
    ) -> Result<(), TeamError> {
        let mut tx = pool.begin().await?;

        // Verify admin status before deleting
        if !User::is_team_admin(pool, user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        // Delete order is important to avoid foreign key constraints

        // Delete user_authorizations for all authorizations linked to stored keys in this team
        sqlx::query(
            r#"
            DELETE FROM user_authorizations 
            WHERE authorization_id IN (
                SELECT a.id 
                FROM authorizations a
                JOIN stored_keys sk ON a.stored_key_id = sk.id
                WHERE sk.team_id = ?1
            )
            "#,
        )
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

        // Delete authorizations for all stored keys in this team
        sqlx::query(
            r#"
            DELETE FROM authorizations 
            WHERE stored_key_id IN (
                SELECT id FROM stored_keys WHERE team_id = ?1
            )
            "#,
        )
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

        // Delete stored keys for this team
        sqlx::query("DELETE FROM stored_keys WHERE team_id = ?1")
            .bind(team_id)
            .execute(&mut *tx)
            .await?;

        // Delete team_users
        sqlx::query("DELETE FROM team_users WHERE team_id = ?1")
            .bind(team_id)
            .execute(&mut *tx)
            .await?;

        // Finally delete the team
        sqlx::query("DELETE FROM teams WHERE id = ?1")
            .bind(team_id)
            .execute(&mut *tx)
            .await?;

        // Commit the transaction
        tx.commit().await?;

        Ok(())
    }

    pub async fn add_user(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
        new_user_public_key: &PublicKey,
        role: TeamUserRole,
    ) -> Result<TeamUser, TeamError> {
        let mut tx = pool.begin().await?;

        // Verify admin status before adding user
        if !User::is_team_admin(pool, user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        // Verify the user isn't already a member of the team
        if sqlx::query_as::<_, TeamUser>(
            r#"
            SELECT * FROM team_users WHERE team_id = ?1 AND user_public_key = ?2
            "#,
        )
        .bind(team_id)
        .bind(new_user_public_key.to_hex())
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
        {
            return Err(TeamError::UserAlreadyMember);
        }

        // First, try to insert the user if they don't exist
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO users (public_key, created_at, updated_at)
            VALUES (?1, datetime('now'), datetime('now'))
            "#,
        )
        .bind(new_user_public_key.to_hex())
        .execute(&mut *tx)
        .await?;

        // Then, insert the team_user relationship
        let team_user = sqlx::query_as::<_, TeamUser>(
            r#"
            INSERT INTO team_users (team_id, user_public_key, role, created_at, updated_at)
            VALUES (?1, ?2, ?3, datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(team_id)
        .bind(new_user_public_key.to_hex())
        .bind(role)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(team_user)
    }

    pub async fn remove_user(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
        user_public_key: &PublicKey,
    ) -> Result<(), TeamError> {
        let mut tx = pool.begin().await?;

        // Verify admin status before removing user
        if !User::is_team_admin(pool, user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        // Delete the team_user relationship
        sqlx::query("DELETE FROM team_users WHERE team_id = ?1 AND user_public_key = ?2")
            .bind(team_id)
            .bind(user_public_key.to_hex())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(())
    }

    pub async fn add_key(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
        name: &str,
        public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> Result<StoredKey, TeamError> {
        let mut tx = pool.begin().await?;

        // Verify admin status before adding key
        if !User::is_team_admin(pool, user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        // TODO: Encrypt the secret key using the master app key
        let key_manager =
            FileKeyManager::new().map_err(|e| EncryptionError::Configuration(e.to_string()))?;

        // Encrypt the secret key
        let encrypted_secret = key_manager
            .encrypt(secret_key.to_secret_hex().as_bytes())
            .await
            .map_err(|e| TeamError::Database(sqlx::Error::Protocol(e.to_string())))?;

        // Insert the key
        let key = sqlx::query_as::<_, StoredKey>(
            r#"
            INSERT INTO stored_keys (team_id, name, public_key, secret_key, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(team_id)
        .bind(name)
        .bind(public_key.to_hex())
        .bind(encrypted_secret)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(key)
    }
}
