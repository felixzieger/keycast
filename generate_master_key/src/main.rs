use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let key: [u8; 32] = rand::thread_rng().gen();
    let encoded = BASE64.encode(key);

    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get parent directory")
        .to_path_buf();
    let key_path = project_root.join("api").join("master.key");

    let mut file = File::create(&key_path).expect("Failed to create key file");
    file.write_all(encoded.as_bytes())
        .expect("Failed to write key");

    println!("Saved new master key to {}", key_path.display());
}
