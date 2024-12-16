use axum::{extract::Path, extract::State, http::StatusCode, Json};
use chrono::DateTime;
use nostr_sdk::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::api::extractors::AuthEvent;
use crate::models::stored_key::StoredKey;
use crate::models::team::{Team, TeamWithRelations};
use crate::models::user::{TeamUser, TeamUserRole};

#[derive(Debug, Serialize)]
pub struct TeamResponse {
    pub id: u32,
    pub name: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct TeamWithRelationsResponse {
    pub team: TeamResponse,
    pub users: Vec<TeamUser>,
    pub stored_keys: Vec<StoredKey>,
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
pub struct RemoveTeammateRequest {
    pub user_public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AddKeyRequest {
    pub public_key: String,
    pub name: String,
    pub secret_key: String,
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

impl From<TeamWithRelations> for TeamWithRelationsResponse {
    fn from(team: TeamWithRelations) -> Self {
        Self {
            team: team.team.into(),
            users: team.team_users,
            stored_keys: team.stored_keys,
        }
    }
}

pub async fn list_teams(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
) -> Result<Json<Vec<TeamWithRelationsResponse>>, (StatusCode, String)> {
    tracing::debug!("Listing teams for user: {}", event.pubkey.to_hex());

    let teams_with_relations = Team::for_user(&pool, &event.pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        teams_with_relations
            .into_iter()
            .map(TeamWithRelationsResponse::from)
            .collect(),
    ))
}

pub async fn create_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<CreateTeamRequest>,
) -> Result<Json<TeamWithRelationsResponse>, (StatusCode, String)> {
    tracing::debug!(
        "Creating team \"{}\" for user: {}",
        request.name,
        event.pubkey.to_hex()
    );

    let team_with_relations = Team::create(&pool, &event.pubkey, &request.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team_with_relations.into()))
}

pub async fn get_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Path(team_id): Path<u32>,
) -> Result<Json<TeamWithRelationsResponse>, (StatusCode, String)> {
    tracing::debug!(
        "Getting team {} for user: {}",
        team_id,
        event.pubkey.to_hex()
    );

    let team_with_relations = Team::get(&pool, &event.pubkey, team_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team_with_relations.into()))
}

pub async fn update_team(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<UpdateTeamRequest>,
) -> Result<Json<TeamResponse>, (StatusCode, String)> {
    tracing::debug!("Updating team for user: {}", event.pubkey.to_hex());

    let team = Team::update(&pool, &event.pubkey, request.id, &request.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(team.into()))
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
    Path(team_id): Path<u32>,
    Json(request): Json<RemoveTeammateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::debug!(
        "Removing user {} from team {}",
        request.user_public_key,
        team_id
    );

    let user_public_key = PublicKey::from_hex(&request.user_public_key)
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

    let public_key = PublicKey::from_hex(&request.public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let secret_key = SecretKey::from_hex(&request.secret_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let key = Team::add_key(
        &pool,
        &event.pubkey,
        team_id,
        &request.name,
        &public_key,
        &secret_key,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(key))
}
