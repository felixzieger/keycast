use crate::api::extractors::AuthEvent;
use crate::models::stored_key::{KeyError, StoredKey};
use crate::models::user::User;
use axum::{extract::State, http::StatusCode, Json};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Serialize)]
pub struct StoredKeyResponse {
    pub id: u32,
    pub name: String,
    pub public_key: String,
    pub secret_key: String,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub team_id: u32,
    pub name: String,
    pub secret_key: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateKeyRequest {
    pub team_id: u32,
    pub name: String,
}

impl From<StoredKey> for StoredKeyResponse {
    fn from(key: StoredKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            public_key: key.public_key,
            secret_key: key.secret_key,
            created_at: key.created_at,
            updated_at: key.updated_at,
        }
    }
}

pub async fn list_keys(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
) -> Result<Json<Vec<StoredKeyResponse>>, (StatusCode, String)> {
    tracing::debug!("Listing keys for user: {}", event.pubkey.to_hex());
    let keys = StoredKey::for_user(&pool, &event.pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        keys.into_iter().map(StoredKeyResponse::from).collect(),
    ))
}

pub async fn create_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<CreateKeyRequest>,
) -> Result<Json<StoredKeyResponse>, (StatusCode, String)> {
    tracing::debug!(
        "Creating key for user {} in team {}",
        event.pubkey.to_hex(),
        request.team_id
    );

    // Check if the user is a member of the team and has admin access
    if !User::is_team_admin(&pool, &event.pubkey, request.team_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
        })?
    {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    }

    let stored_key = StoredKey::create(request.team_id, request.name, request.secret_key, &pool)
        .await
        .map_err(|e| match e {
            KeyError::NostrKey(_) => (StatusCode::BAD_REQUEST, "Invalid secret key".to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        })?;

    Ok(Json(stored_key.into()))
}

pub async fn update_key(
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
    Json(request): Json<UpdateKeyRequest>,
) -> Result<Json<StoredKeyResponse>, (StatusCode, String)> {
    tracing::debug!("Updating key for user: {}", event.pubkey.to_hex());

    let stored_key = StoredKey::update(&pool, &event.pubkey, request.team_id, &request.name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(stored_key.into()))
}
