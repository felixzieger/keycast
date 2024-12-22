use crate::encryption::KeyManagerError;
use crate::types::authorization::{
    Authorization, AuthorizationError, AuthorizationWithPolicy, AuthorizationWithRelations,
    UserAuthorization,
};
use crate::types::permission::{Permission, PermissionError, PolicyPermission};
use crate::types::policy::{Policy, PolicyError, PolicyWithPermissions};
use crate::types::stored_key::StoredKey;
use crate::types::user::{TeamUser, TeamUserRole, User, UserError};
use chrono::DateTime;
use nostr_sdk::prelude::*;
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
    Encryption(#[from] KeyManagerError),

    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),

    #[error("Permission error: {0}")]
    Permission(#[from] PermissionError),

    #[error("Serde JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Authorization error: {0}")]
    Authorization(#[from] AuthorizationError),
}

/// A team is a collection of users, stored keys, policies, and permissions
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Team {
    /// The id of the team
    pub id: u32,
    /// The name of the team
    pub name: String,
    /// The date and time the team was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the team was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TeamWithRelations {
    pub team: Team,
    pub team_users: Vec<TeamUser>, // Use team_user here so we get the role
    pub stored_keys: Vec<StoredKey>,
    pub policies: Vec<PolicyWithPermissions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyWithRelations {
    pub team: Team,
    pub stored_key: StoredKey,
    pub authorizations: Vec<AuthorizationWithRelations>,
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

            // Get policies for this team
            let policies = Team::get_policies_with_permissions(&pool, team.id).await?;

            teams_with_relations.push(TeamWithRelations {
                team,
                team_users,
                stored_keys,
                policies,
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
        if !User::is_team_admin(user_pubkey, team_id).await? {
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

        // Get policies for this team
        let policies = Team::get_policies_with_permissions(team_id).await?;

        Ok(TeamWithRelations {
            team,
            team_users,
            stored_keys,
            policies,
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

        // Then, create the team_user relationship with admin role
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

        // Finally, create the default policy, default permission (all permissions allowed), and join them
        let policy = sqlx::query_as::<_, Policy>(
            r#"
            INSERT INTO policies (team_id, name, created_at, updated_at)
            VALUES (?1, 'All Access', datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(team.id)
        .fetch_one(&mut *tx)
        .await?;

        let allowed_kinds_config = permissions::allowed_kinds::AllowedKindsConfig::default();
        let permission = sqlx::query_as::<_, Permission>(
            r#"
            INSERT INTO permissions (identifier, config, created_at, updated_at)
            VALUES ('allowed_kinds', ?1, datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(serde_json::to_value(allowed_kinds_config)?)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query_as::<_, PolicyPermission>(
            r#"
            INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
            VALUES (?1, ?2, datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(policy.id)
        .bind(permission.id)
        .fetch_one(&mut *tx)
        .await?;

        let policy_with_permissions = PolicyWithPermissions {
            policy,
            permissions: vec![permission],
        };

        // Commit the transaction
        tx.commit().await.map_err(|e| {
            tracing::error!("Failed to commit transaction: {}", e);
            TeamError::from(e)
        })?;

        Ok(TeamWithRelations {
            team,
            team_users: vec![team_user],
            stored_keys: vec![],
            policies: vec![policy_with_permissions],
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
        if !User::is_team_admin(user_pubkey, team_id).await? {
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
        if !User::is_team_admin(user_pubkey, team_id).await? {
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

        // Delete policy_permissions for all policies in this team
        sqlx::query(
            r#"
            DELETE FROM policy_permissions 
            WHERE policy_id IN (
                SELECT id FROM policies WHERE team_id = ?1
            )
            "#,
        )
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

        // Delete permissions that were associated with this team's policies
        sqlx::query(
            r#"
            DELETE FROM permissions 
            WHERE id IN (
                SELECT permission_id 
                FROM policy_permissions 
                WHERE policy_id IN (
                    SELECT id FROM policies WHERE team_id = ?1
                )
            )
            "#,
        )
        .bind(team_id)
        .execute(&mut *tx)
        .await?;

        // Delete policies for this team
        sqlx::query("DELETE FROM policies WHERE team_id = ?1")
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
        if !User::is_team_admin(user_pubkey, team_id).await? {
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
        if !User::is_team_admin(user_pubkey, team_id).await? {
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
        if !User::is_team_admin(user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        // Encrypt the secret key
        let key_manager = get_key_manager().unwrap();
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

    pub async fn remove_key(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
        pubkey: &PublicKey,
    ) -> Result<(), TeamError> {
        let mut tx = pool.begin().await?;

        // Verify admin status before removing key
        if !User::is_team_admin(user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        // Delete all user_authorizations for this key
        sqlx::query("DELETE FROM user_authorizations WHERE authorization_id IN (SELECT id FROM authorizations WHERE stored_key_id = ?1)")
            .bind(pubkey.to_hex())
            .execute(&mut *tx)
            .await?;

        // Delete all authorizations for this key
        sqlx::query("DELETE FROM authorizations WHERE stored_key_id = ?1")
            .bind(pubkey.to_hex())
            .execute(&mut *tx)
            .await?;

        // Delete the key
        sqlx::query("DELETE FROM stored_keys WHERE team_id = ?1 AND public_key = ?2")
            .bind(team_id)
            .bind(pubkey.to_hex())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn get_key_with_relations(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        team_id: u32,
        pubkey: &PublicKey,
    ) -> Result<KeyWithRelations, TeamError> {
        // Verify admin status before getting key
        if !User::is_team_admin(user_pubkey, team_id).await? {
            return Err(TeamError::NotAuthorized);
        }

        let team = sqlx::query_as::<_, Team>(
            r#"
            SELECT * FROM teams WHERE id = ?1
            "#,
        )
        .bind(team_id)
        .fetch_one(pool)
        .await?;

        let stored_key = sqlx::query_as::<_, StoredKey>(
            r#"
            SELECT * FROM stored_keys WHERE team_id = ?1 AND public_key = ?2
            "#,
        )
        .bind(team_id)
        .bind(pubkey.to_hex())
        .fetch_one(pool)
        .await?;

        // First fetch authorizations with policies
        let base_authorizations = sqlx::query_as::<_, AuthorizationWithPolicy>(
            r#"
            SELECT 
                a.*,
                p.*
            FROM authorizations a
            LEFT JOIN policies p ON p.id = a.policy_id
            WHERE a.stored_key_id = ?1
            "#,
        )
        .bind(stored_key.id)
        .fetch_all(pool)
        .await?;

        // Then fetch users for each authorization and combine
        let mut complete_authorizations = Vec::new();
        for auth in base_authorizations {
            let users = sqlx::query_as::<_, UserAuthorization>(
                r#"
                SELECT user_public_key, created_at, updated_at
                FROM user_authorizations
                WHERE authorization_id = ?1
                "#,
            )
            .bind(auth.authorization.id)
            .fetch_all(pool)
            .await?;

            complete_authorizations.push(AuthorizationWithRelations {
                authorization: auth.authorization.clone(),
                policy: auth.policy,
                users,
                bunker_connection_string: auth.authorization.bunker_connection_string().await?,
            });
        }

        Ok(KeyWithRelations {
            team,
            stored_key,
            authorizations: complete_authorizations,
        })
    }

    pub async fn get_policies_with_permissions(
        pool: &SqlitePool,
        team_id: u32,
    ) -> Result<Vec<PolicyWithPermissions>, TeamError> {
        // First fetch policies
        let policies = sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE team_id = ?1")
            .bind(team_id)
            .fetch_all(pool)
            .await?;

        // Then fetch permissions for each policy
        let mut policies_with_permissions = Vec::new();
        for policy in policies {
            let permissions = sqlx::query_as::<_, Permission>(
                "SELECT p.* FROM permissions p 
                 JOIN policy_permissions pp ON pp.permission_id = p.id 
                 WHERE pp.policy_id = ?1",
            )
            .bind(policy.id)
            .fetch_all(pool)
            .await?;

            policies_with_permissions.push(PolicyWithPermissions {
                policy,
                permissions,
            });
        }

        Ok(policies_with_permissions)
    }
}
