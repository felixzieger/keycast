use axum::{extract::Path, http::StatusCode, Json};
use chrono::DateTime;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;

use crate::api::extractors::AuthEvent;
use keycast_core::types::authorization::Authorization;
use keycast_core::types::policy::PolicyWithPermissions;
use keycast_core::types::stored_key::StoredKey;
use keycast_core::types::team::{KeyWithRelations, Team, TeamWithRelations};
use keycast_core::types::user::{TeamUser, TeamUserRole, User};

#[derive(Debug, Serialize)]
pub struct TeamResponse {
    pub id: u32,
    pub name: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub id: u32,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AddTeammateRequest {
    pub user_public_key: String,
    pub role: TeamUserRole,
}

#[derive(Debug, Deserialize)]
pub struct AddKeyRequest {
    pub name: String,
    pub secret_key: String,
}

#[derive(Debug, Deserialize)]
pub struct PermissionParams {
    pub identifier: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub permissions: Vec<PermissionParams>,
}

#[derive(Debug, Deserialize)]
pub struct AddAuthorizationRequest {
    pub policy_id: u32,
    pub relays: Vec<String>,
    pub max_uses: Option<i32>,
    #[serde(default)]
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<Team> for TeamResponse {
    fn from(team: Team) -> Self {
        Self {
            id: team.id,
            name: team.name,
            created_at: team.created_at,
            updated_at: team.updated_at,
        }
    }
}

pub async fn list_teams(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
) -> Result<Json<Vec<TeamWithRelations>>, (StatusCode, String)> {
    let user = User::find_by_pubkey(&pool, &event.pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let teams_with_relations = user.teams(&pool).await?;

    Ok(Json(teams_with_relations))
}

pub async fn create_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<CreateTeamRequest>,
) -> Result<Json<TeamWithRelations>, (StatusCode, String)> {
    let mut tx = pool.begin().await?;

    let user_pubkey = event.pubkey;

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

    Ok(Json(TeamWithRelations {
        team,
        team_users: vec![team_user],
        stored_keys: vec![],
        policies: vec![policy_with_permissions],
    }))
}

pub async fn get_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
) -> Result<Json<TeamWithRelations>, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let team_with_relations = Team::find_with_relations(&pool, team_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team_with_relations))
}

pub async fn update_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<UpdateTeamRequest>,
) -> Result<Json<Team>, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, request.id).await?;

    let mut tx = pool.begin().await?;

    let team = sqlx::query_as::<_, Team>(
        r#"
        UPDATE teams SET name = ?1 WHERE id = ?2
        RETURNING *
        "#,
    )
    .bind(request.name)
    .bind(request.id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(team))
}

pub async fn delete_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let mut tx = pool.begin().await?;

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

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_user(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
    Json(request): Json<AddTeammateRequest>,
) -> Result<Json<TeamUser>, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let mut tx = pool.begin().await?;

    let new_user_public_key = PublicKey::from_hex(&request.user_public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

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
    Ok(Json(team_user))
}

pub async fn remove_user(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, user_public_key)): Path<(u32, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let mut tx = pool.begin().await?;

    let removed_user_public_key = PublicKey::from_hex(&user_public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Delete the team_user relationship
    sqlx::query("DELETE FROM team_users WHERE team_id = ?1 AND user_public_key = ?2")
        .bind(team_id)
        .bind(removed_user_public_key.to_hex())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
    Json(request): Json<AddKeyRequest>,
) -> Result<Json<StoredKey>, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let mut tx = pool.begin().await?;

    let keys =
        Keys::parse(&request.secret_key).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Encrypt the secret key
    let key_manager = get_key_manager().unwrap();
    let encrypted_secret = key_manager
        .encrypt(keys.secret_key().as_secret_bytes())
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
    .bind(request.name)
    .bind(keys.public_key().to_hex())
    .bind(encrypted_secret)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(key))
}

pub async fn remove_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let mut tx = pool.begin().await?;

    let removed_stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Delete all user_authorizations for this key
    sqlx::query("DELETE FROM user_authorizations WHERE authorization_id IN (SELECT id FROM authorizations WHERE stored_key_id = ?1)")
    .bind(removed_stored_key_public_key.to_hex())
    .execute(&mut *tx)
    .await?;

    // Delete all authorizations for this key
    sqlx::query("DELETE FROM authorizations WHERE stored_key_id = ?1")
        .bind(removed_stored_key_public_key.to_hex())
        .execute(&mut *tx)
        .await?;

    // Delete the key
    sqlx::query("DELETE FROM stored_keys WHERE team_id = ?1 AND public_key = ?2")
        .bind(team_id)
        .bind(removed_stored_key_public_key.to_hex())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
) -> Result<Json<KeyWithRelations>, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let mut tx = pool.begin().await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

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
    .bind(stored_key_public_key.to_hex())
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

pub async fn add_authorization(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
    Json(request): Json<AddAuthorizationRequest>,
) -> Result<Json<Authorization>, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;

    let stored_key_public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let mut tx = pool.begin().await?;

    let stored_key = sqlx::query_as::<_, StoredKey>(
        r#"
            SELECT * FROM stored_keys WHERE team_id = ?1 AND public_key = ?2
            "#,
    )
    .bind(team_id)
    .bind(stored_key_public_key.to_hex())
    .fetch_one(&mut *tx)
    .await?;

    // Verify policy exists
    let policy_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM policies WHERE id = ?1)")
            .bind(request.policy_id)
            .fetch_one(&mut *tx)
            .await?;

    if !policy_exists {
        return Err(TeamError::Policy(PolicyError::NotFound));
    }

    // Create bunker keys for this authorization
    let bunker_keys = Keys::generate();

    // Encrypt the secret key
    let key_manager = get_key_manager().unwrap();
    let encrypted_bunker_secret = key_manager
        .encrypt(bunker_keys.secret_key().as_secret_bytes())
        .await
        .map_err(|e| TeamError::Database(sqlx::Error::Protocol(e.to_string())))?;

    // create a secret uuid for the authorization connection string
    let secret = uuid::Uuid::new_v4().to_string();

    // Create authorization
    let authorization = sqlx::query_as::<_, Authorization>(
            r#"
            INSERT INTO authorizations (stored_key_id, policy_id, secret, bunker_public_key, bunker_secret, relays, max_uses, expires_at, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, datetime('now'), datetime('now'))
            RETURNING *
            "#,
        )
        .bind(stored_key.id)
        .bind(request.policy_id)
        .bind(secret)
        .bind(bunker_keys.public_key().to_hex())
        .bind(encrypted_bunker_secret)
        .bind(serde_json::to_string(&request.relays)?)
        .bind(request.max_uses)
        .bind(request.expires_at)
        .fetch_one(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Json(authorization))
}

pub async fn add_policy(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
    Json(request): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyWithPermissions>, (StatusCode, String)> {
    verify_admin(&pool, &event.pubkey, team_id).await?;
    let mut tx = pool.begin().await?;

    // Create the permissions
    let mut permissions = Vec::new();
    for permission in request.permissions {
        // Skip if the permission identifier is not in AVAILABLE_PERMISSIONS
        if !permissions::AVAILABLE_PERMISSIONS.contains(&permission.identifier.as_str()) {
            tracing::warn!(
                "Skipping unknown permission identifier: {}",
                permission.identifier
            );
            continue;
        }

        let permission = sqlx::query_as::<_, Permission>(
            "INSERT INTO permissions (identifier, config, created_at, updated_at) VALUES (?1, ?2, datetime('now'), datetime('now')) RETURNING *",
        )
        .bind(permission.identifier)
        .bind(permission.config)
        .fetch_one(&mut *tx)
        .await?;

        permissions.push(permission);
    }

    // Create the policy
    let policy = sqlx::query_as::<_, Policy>(
        "INSERT INTO policies (team_id, name, created_at, updated_at) VALUES (?1, ?2, datetime('now'), datetime('now')) RETURNING *",
    )
    .bind(team_id)
    .bind(request.name)
    .fetch_one(&mut *tx)
    .await?;

    // create the policy permissions
    for permission in &permissions {
        sqlx::query(
            "INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at) VALUES (?1, ?2, datetime('now'), datetime('now'))",
        )
        .bind(policy.id)
        .bind(permission.id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(Json(PolicyWithPermissions {
        policy,
        permissions,
    }))
}

pub async fn verify_admin(
    pool: &SqlitePool,
    pubkey: &PublicKey,
    team_id: u32,
) -> Result<(), (StatusCode, &str)> {
    if !User::is_team_admin(pool, pubkey, team_id).await? {
        return Err((
            StatusCode::FORBIDDEN,
            "You are not authorized to access this team",
        ));
    }
    Ok(())
}
