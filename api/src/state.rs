use crate::database::DatabaseError;
use crate::encryption::{KeyManager, KeyManagerError};
use once_cell::sync::OnceCell;
use sqlx::SqlitePool;
use std::sync::Arc;

pub struct KeycastState {
    pub db: SqlitePool,
    pub key_manager: Box<dyn KeyManager>,
}

pub static KEYCAST_STATE: OnceCell<Arc<KeycastState>> = OnceCell::new();

pub fn get_db_pool() -> Result<&'static SqlitePool, DatabaseError> {
    KEYCAST_STATE
        .get()
        .map(|state| &state.db)
        .ok_or(DatabaseError::NotInitialized)
}

pub fn get_key_manager() -> Result<&'static dyn KeyManager, KeyManagerError> {
    KEYCAST_STATE
        .get()
        .map(|db| db.key_manager.as_ref())
        .ok_or(KeyManagerError::NotInitialized)
}
