use axum::{extract::Path, http::StatusCode, Json};
use chrono::DateTime;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;

use crate::api::extractors::AuthEvent;
use core::types::authorization::Authorization;
use core::types::policy::PolicyWithPermissions;
use core::types::stored_key::StoredKey;
use core::types::team::{KeyWithRelations, Team, TeamWithRelations};
use core::types::user::{TeamUser, TeamUserRole, User};

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
    let teams_with_relations = Team::for_user(&pool, &event.pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(teams_with_relations))
}

pub async fn create_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<CreateTeamRequest>,
) -> Result<Json<TeamWithRelations>, (StatusCode, String)> {
    tracing::debug!(
        "Creating team \"{}\" for user: {}",
        request.name,
        event.pubkey.to_hex()
    );

    let team_with_relations = Team::create(&pool, &event.pubkey, &request.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team_with_relations))
}

pub async fn get_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
) -> Result<Json<TeamWithRelations>, (StatusCode, String)> {
    tracing::debug!(
        "Getting team {} for user: {}",
        team_id,
        event.pubkey.to_hex()
    );

    let team_with_relations = Team::get(&pool, &event.pubkey, team_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team_with_relations))
}

pub async fn update_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<UpdateTeamRequest>,
) -> Result<Json<Team>, (StatusCode, String)> {
    tracing::debug!("Updating team for user: {}", event.pubkey.to_hex());

    let team = Team::update(&pool, &event.pubkey, request.id, &request.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team))
}

pub async fn delete_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::debug!("Deleting team for user: {}", event.pubkey.to_hex());

    Team::delete(&pool, &event.pubkey, team_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_user(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
    Json(request): Json<AddTeammateRequest>,
) -> Result<Json<TeamUser>, (StatusCode, String)> {
    tracing::debug!(
        "Adding user \"{}\" to team {}",
        request.user_public_key,
        team_id,
    );

    let user_public_key = PublicKey::from_hex(&request.user_public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let user = Team::add_user(
        &pool,
        &event.pubkey,
        team_id,
        &user_public_key,
        request.role,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(user))
}

pub async fn remove_user(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, user_public_key)): Path<(u32, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::debug!("Removing user {} from team {}", user_public_key, team_id);

    let user_public_key = PublicKey::from_hex(&user_public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Team::remove_user(&pool, &event.pubkey, team_id, &user_public_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
    Json(request): Json<AddKeyRequest>,
) -> Result<Json<StoredKey>, (StatusCode, String)> {
    tracing::debug!("Adding key to team for user: {}", event.pubkey.to_hex());

    let keys =
        Keys::parse(&request.secret_key).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let key = Team::add_key(
        &pool,
        &event.pubkey,
        team_id,
        &request.name,
        &keys.public_key(),
        keys.secret_key(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(key))
}

pub async fn remove_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::debug!("Removing key {} from team {}", pubkey, team_id);

    let pubkey =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Team::remove_key(&pool, &event.pubkey, team_id, &pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
) -> Result<Json<KeyWithRelations>, (StatusCode, String)> {
    tracing::debug!("Getting key {} for team {}", pubkey, team_id);

    let pubkey =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let key_with_relations = Team::get_key_with_relations(&pool, &event.pubkey, team_id, &pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(key_with_relations))
}

pub async fn add_authorization(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
    Json(request): Json<AddAuthorizationRequest>,
) -> Result<Json<Authorization>, (StatusCode, String)> {
    // Verify admin status before getting key
    if !User::is_team_admin(&pool, &event.pubkey, team_id).await? {
        return Err(TeamError::NotAuthorized);
    }

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
    // Verify admin status before adding policy
    if !User::is_team_admin(pool, user_pubkey, team_id).await? {
        return Err(TeamError::NotAuthorized);
    }

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
