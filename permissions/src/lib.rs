pub mod allowed_kinds;
pub mod content_filter;
pub mod encrypt_to_self;

/// The list of available permissions
pub static AVAILABLE_PERMISSIONS: [&str; 3] =
    ["allowed_kinds", "content_filter", "encrypt_to_self"];
