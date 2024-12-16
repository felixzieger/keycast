use crate::api::http::extract_auth_event_from_header;
use axum::http::StatusCode;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use nostr_sdk::Event;

// Create a local wrapper type
pub struct AuthEvent(pub Event);

// Extract the auth event from the request
#[async_trait]
impl<S> FromRequestParts<S> for AuthEvent
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .ok_or((
                StatusCode::UNAUTHORIZED,
                "Missing authorization header".to_string(),
            ))?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid authorization header".to_string(),
                )
            })?;

        if !auth_header.starts_with("Nostr ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid authorization scheme".to_string(),
            ));
        }

        // Extract pubkey from the auth header
        let event = extract_auth_event_from_header(auth_header)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

        tracing::debug!("Extracted auth event: {:#?}", event);
        Ok(AuthEvent(event))
    }
}
