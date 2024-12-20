use axum::{extract::Path, http::StatusCode, Json};
use chrono::DateTime;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::Utc;

use crate::api::extractors::AuthEvent;
use crate::models::authorization::Authorization;
use crate::models::policy::PolicyWithPermissions;
use crate::models::stored_key::StoredKey;
use crate::models::team::{KeyWithRelations, Team, TeamWithRelations};
use crate::models::user::{TeamUser, TeamUserRole};

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
    AuthEvent(event): AuthEvent,
) -> Result<Json<Vec<TeamWithRelations>>, (StatusCode, String)> {
    tracing::debug!("Listing teams for user: {}", event.pubkey.to_hex());

    let teams_with_relations = Team::for_user(&event.pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(teams_with_relations))
}

pub async fn create_team(
    AuthEvent(event): AuthEvent,
    Json(request): Json<CreateTeamRequest>,
) -> Result<Json<TeamWithRelations>, (StatusCode, String)> {
    tracing::debug!(
        "Creating team \"{}\" for user: {}",
        request.name,
        event.pubkey.to_hex()
    );

    let team_with_relations = Team::create(&event.pubkey, &request.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team_with_relations))
}

pub async fn get_team(
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
) -> Result<Json<TeamWithRelations>, (StatusCode, String)> {
    tracing::debug!(
        "Getting team {} for user: {}",
        team_id,
        event.pubkey.to_hex()
    );

    let team_with_relations = Team::get(&event.pubkey, team_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team_with_relations))
}

pub async fn update_team(
    AuthEvent(event): AuthEvent,
    Json(request): Json<UpdateTeamRequest>,
) -> Result<Json<Team>, (StatusCode, String)> {
    tracing::debug!("Updating team for user: {}", event.pubkey.to_hex());

    let team = Team::update(&event.pubkey, request.id, &request.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team))
}

pub async fn delete_team(
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::debug!("Deleting team for user: {}", event.pubkey.to_hex());

    Team::delete(&event.pubkey, team_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_user(
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

    let user = Team::add_user(&event.pubkey, team_id, &user_public_key, request.role)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(user))
}

pub async fn remove_user(
    AuthEvent(event): AuthEvent,
    Path((team_id, user_public_key)): Path<(u32, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::debug!("Removing user {} from team {}", user_public_key, team_id);

    let user_public_key = PublicKey::from_hex(&user_public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Team::remove_user(&event.pubkey, team_id, &user_public_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_key(
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
    Json(request): Json<AddKeyRequest>,
) -> Result<Json<StoredKey>, (StatusCode, String)> {
    tracing::debug!("Adding key to team for user: {}", event.pubkey.to_hex());

    let keys =
        Keys::parse(&request.secret_key).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let key = Team::add_key(
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
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::debug!("Removing key {} from team {}", pubkey, team_id);

    let pubkey =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Team::remove_key(&event.pubkey, team_id, &pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_key(
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
) -> Result<Json<KeyWithRelations>, (StatusCode, String)> {
    tracing::debug!("Getting key {} for team {}", pubkey, team_id);

    let pubkey =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let key_with_relations = Team::get_key_with_relations(&event.pubkey, team_id, &pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(key_with_relations))
}

pub async fn add_authorization(
    AuthEvent(event): AuthEvent,
    Path((team_id, pubkey)): Path<(u32, String)>,
    Json(request): Json<AddAuthorizationRequest>,
) -> Result<Json<Authorization>, (StatusCode, String)> {
    tracing::debug!(
        "Adding authorization to key {} for team {}",
        pubkey,
        team_id
    );

    let public_key =
        PublicKey::from_hex(&pubkey).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let authorization = Team::add_authorization(&event.pubkey, team_id, &public_key, request)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(authorization))
}

pub async fn add_policy(
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
    Json(request): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyWithPermissions>, (StatusCode, String)> {
    tracing::debug!("Creating policy for team {}", team_id);

    let policy_with_permissions = Team::add_policy(&event.pubkey, team_id, request)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(policy_with_permissions))
}
