use crate::cli::CliError;
use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Args)]
pub struct StoredKeyCommand {
    #[clap(subcommand)]
    pub command: StoredKeySubcommand,
}

/// Commands for managing stored keys
#[derive(Debug, Subcommand)]
pub enum StoredKeySubcommand {
    /// Create a new stored key
    Create(CreateStoredKeyParams),
    /// Retrieve and decrypt a stored key
    Get(PrivilegedUpdateStoredKeyParams),
    /// Delete a stored key
    Delete(PrivilegedUpdateStoredKeyParams),
    /// Sign a message
    Sign(SignEventParams),
    /// Encrypt a message
    Encrypt(EncryptParams),
    /// Decrypt a message
    Decrypt(DecryptParams),
}

#[derive(Debug, Args)]
pub struct CreateStoredKeyParams {
    /// The team id to create the key for
    #[arg(short, long)]
    team_id: u32,

    /// The name of the key
    #[arg(short, long)]
    name: String,

    /// The secret key to store in hex format
    #[arg(short, long)]
    secret_key: String,
}

#[derive(Debug, Args)]
pub struct PrivilegedUpdateStoredKeyParams {
    /// The secret key to get
    #[arg(short, long)]
    secret_key: String,
}

#[derive(Debug, Args)]
pub struct SignEventParams {
    /// The encrypted secret key to sign the event with
    #[arg(short, long)]
    secret_key: String,

    /// JSON string of the event to sign
    #[arg(short, long)]
    event: String,
}

#[derive(Debug, Default, Clone, ValueEnum)]
pub enum EncryptionMethod {
    Nip04,
    #[default]
    Nip44,
}

#[derive(Debug, Args)]
pub struct EncryptParams {
    /// The encryption method to use
    #[arg(short, long, default_value = "nip44")]
    encryption_method: EncryptionMethod,

    /// The secret key to encrypt the message with
    #[arg(short, long)]
    secret_key: String,

    /// Receipient public key in hex or bech32 format
    #[arg(short, long)]
    recipient_public_key: String,

    /// The content to encrypt
    #[arg(short, long)]
    content: String,
}

#[derive(Debug, Args)]
pub struct DecryptParams {
    /// The encryption method to use
    #[arg(short, long, default_value = "nip44")]
    encryption_method: EncryptionMethod,

    /// The secret key to decrypt the message with
    #[arg(short, long)]
    secret_key: String,

    /// Sender public key in hex or bech32 format
    #[arg(short, long)]
    sender_public_key: String,

    /// The encrypted content to decrypt
    #[arg(short, long)]
    encrypted_content: String,
}

impl StoredKeyCommand {
    #[allow(unused)]
    pub async fn execute(self) -> Result<(), CliError> {
        todo!("Implement StoredKeyCommand");
    }
}
