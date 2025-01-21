//! Authentication module for managing API keys.
//!
//! This module provides functionality to generate, hash, and verify API keys,
//! as well as to load and save keys from a JSON file. Argon2 has been chosen for hashing 'slow'
//! giving resistance to GPU cracking attacks and its ability to adjust the time and memory
//! cost of hashing. The keys are stored in a JSON file for persistence.
//!
//! # Constants
//! - `KEYS_FILE`: Path to the JSON file storing the keys.
//!
//! # Structs
//! - `KeyEntry`: Represents an API key entry with label, public key, hash, expiry, and endpoints.
//!
//! # Functions
//! - `generate_key`: Generates a new API key, hashes it, and saves it to the keys file.
//! - `hash_key`: Hashes a given key using Argon2.
//! - `key_exists`: Checks if a given public key exists in the provided list of keys.

use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{Utc, DateTime};
use password_hash::SaltString;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::fs;

const KEYS_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/keys.json");

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub label: String,
    pub pub_key: String,
    pub hash: String,
    pub expiry: Option<DateTime<Utc>>,
    pub endpoints: Vec<String>,
}

/// Generates a new API key, hashes it, and saves it to the keys file.
///
/// # Arguments
///
/// * `label` - A string slice that holds the label for the key.
/// * `expiry` - An optional string slice that holds the expiry date in RFC3339 format.
/// * `endpoints` - A vector of strings representing the endpoints associated with the key.
///
/// # Example
///
/// ```
/// let label = "example_key";
/// let expiry = Some("2023-12-31T23:59:59Z".to_string());
/// let endpoints = vec!["/api/v1/resource".to_string()];
/// add_auth_key(label, expiry, endpoints).await;
/// ```
pub async fn add_auth_key(label: &str, expiry: Option<String>, endpoints: Vec<String>) {
    let (priv_key, pub_key) = generate_key_pair();

    let expiry_datetime = expiry
        .as_deref()
        .map(|e| DateTime::parse_from_rfc3339(e).expect("Invalid expiry format").with_timezone(&Utc));

    let hashed_key = hash_key(&priv_key);
    let key_entry = KeyEntry {
        label: label.to_string(),
        pub_key: pub_key.to_string(),
        hash: hashed_key,
        expiry: expiry_datetime,
        endpoints,
    };

    let mut keys = load_keys().await;
    keys.push(key_entry);
    save_keys(&keys).await;

    println!("Generated Public Key: {}", pub_key);
    println!("Generated Private Key: {}", priv_key);

    println!("API key added to keys.json");
}

/// Removes an API key from the keys file.
///
/// # Arguments
///
/// * `label` - A string slice that holds the label for the key.
///
pub async fn remove_auth_key(label: &str) {
    let mut keys = load_keys().await;
    keys.retain(|k| k.label != label);
    save_keys(&keys).await;
}

/// Generates a pair of private and public keys.
///
/// # Returns
///
/// A tuple containing the private key and the public key as `String`s.
fn generate_key_pair() -> (String, String) {
    (generate_priv_key(), generate_pub_key())
}

/// Generates a new private key.
///
/// # Returns
///
/// A `String` representing the newly generated private key.
fn generate_priv_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generates a new public key.
///
/// # Returns
///
/// A `String` representing the newly generated public key.
fn generate_pub_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Hashes a given key using Argon2.
///
/// Important: The random Salt works because Argon2 stores the salt in the hash output.
///
/// # Arguments
///
/// * `key` - The key to be hashed.
///
/// # Returns
///
/// A `String` representing the hashed key.
///
fn hash_key(key: &str) -> String {
    let salt = SaltString::generate(&mut OsRng); // Generate a random salt
    let argon2 = Argon2::default(); // Use default Argon2 parameters
    argon2
        .hash_password(key.as_bytes(), &salt)
        .expect("Failed to hash key")
        .to_string()
}

/// Checks if a given public key exists in the provided list of keys.
///
/// # Arguments
///
/// * `keys` - A reference to a vector of `KeyEntry` objects.
/// * `pub_key` - The public key to check.
///
/// # Returns
///
/// A `bool` indicating whether the key exists.
///
pub async fn key_exists(keys: Arc<Vec<KeyEntry>>, pub_key: String) -> bool {
    for entry in keys.iter() {
        if entry.pub_key == pub_key {
            return true; // Key exists
        }
    }
    false
}

/// Checks if a given key is unexpired.
///
/// # Arguments
///
/// * `keys` - A reference to a vector of `KeyEntry` objects.
/// * `pub_key` - The public key to check.
///
/// # Returns
///
/// A `bool` indicating whether the key is unexpired.
///
pub async fn key_is_unexpired(keys: Arc<Vec<KeyEntry>>, pub_key: String) -> bool {
    for entry in keys.iter() {
        if entry.pub_key == pub_key {
            if let Some(expiry) = entry.expiry {
                return expiry > Utc::now(); // Key is unexpired
            } else {
                return true; // Key has no expiry
            }
        }
    }
    false
}

/// Checks if a given key has access to the requested endpoint.
///
/// # Arguments
///
/// * `keys` - A reference to a vector of `KeyEntry` objects.
/// * `pub_key` - The public key to check.
/// * `endpoint` - The requested endpoint.
///
/// # Returns
///
/// A `bool` indicating whether the key has access to the endpoint.
///
pub async fn key_has_endpoint_access(keys: Arc<Vec<KeyEntry>>, pub_key: String, endpoint: &str) -> bool {
    for entry in keys.iter() {
        if entry.pub_key == pub_key {
            return entry.endpoints.contains(&endpoint.to_string());
        }
    }
    false
}

/// Validates a key against the stored keys.
///
/// # Arguments
///
/// * `keys` - A reference to a vector of `KeyEntry` objects.
/// * `pub_key` - The public key to validate.
/// * `priv_key` - The private key to validate.
///
/// # Returns
///
/// A `bool` indicating whether the key is valid.
///
pub async fn validate_key(keys: Arc<Vec<KeyEntry>>, pub_key: String, priv_key: String) -> bool {
    for entry in keys.iter() {
        if entry.pub_key == pub_key {
            return verify_key(priv_key.as_str(), entry.hash.as_str());
        }
    }
    false
}

/// Verifies a plaintext key against a hashed key.
///
/// # Arguments
///
/// * `plaintext_key` - The plaintext key to verify.
/// * `hashed_key` - The hashed key to verify against.
///
/// # Returns
///
/// A `bool` indicating whether the key is valid.
///
fn verify_key(plaintext_key: &str, hashed_key: &str) -> bool {
    let parsed_hash = PasswordHash::new(hashed_key).expect("Failed to parse hashed key");
    Argon2::default()
        .verify_password(plaintext_key.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Loads keys from the keys file
///
/// # Returns
///
/// A vector of `KeyEntry` objects.
///
pub async fn load_keys() -> Vec<KeyEntry> {
    match fs::read_to_string(KEYS_FILE).await {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|_| Vec::new()),
        Err(_) => Vec::new(), // Return an empty vector if the file doesn't exist
    }
}

/// Saves keys to the keys file
///
/// # Arguments
///
/// * `keys` - A reference to a vector of `KeyEntry` objects.
///
/// # Panics
///
/// This function will panic if the keys cannot be serialized or written to the file.
///
async fn save_keys(keys: &[KeyEntry]) {
    let contents = serde_json::to_string_pretty(keys).expect("Failed to serialize keys");
    fs::write(KEYS_FILE, contents).await.expect("Failed to write keys.json");
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_key() {
        let key = "test_key";
        let hashed_key = hash_key(key);
        assert!(!hashed_key.is_empty());
        let parsed_hash = PasswordHash::new(&hashed_key).expect("Failed to parse hashed key");
        assert!(Argon2::default()
            .verify_password(key.as_bytes(), &parsed_hash)
            .is_ok());
    }

    #[test]
    fn test_hash_key_different_inputs() {
        let key1 = "test_key_1";
        let key2 = "test_key_2";
        let hashed_key1 = hash_key(key1);
        let hashed_key2 = hash_key(key2);
        assert!(!hashed_key1.is_empty());
        assert!(!hashed_key2.is_empty());
        assert_ne!(hashed_key1, hashed_key2);
    }

    #[test]
    fn test_hash_key_same_input() {
        let key = "test_key";
        let hashed_key1 = hash_key(key);
        let hashed_key2 = hash_key(key);
        assert!(!hashed_key1.is_empty());
        assert!(!hashed_key2.is_empty());
        assert_ne!(hashed_key1, hashed_key2);
    }

    #[test]
    fn test_hash_key_special_characters() {
        let key = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
        let hashed_key = hash_key(key);
        assert!(!hashed_key.is_empty());
        let parsed_hash = PasswordHash::new(&hashed_key).expect("Failed to parse hashed key");
        assert!(Argon2::default()
            .verify_password(key.as_bytes(), &parsed_hash)
            .is_ok());
    }

    #[test]
    fn test_generate_key_pair() {
        let (priv_key, pub_key) = generate_key_pair();
        assert!(!priv_key.is_empty());
        assert!(!pub_key.is_empty());
        assert_ne!(priv_key, pub_key);
    }

    #[tokio::test]
    async fn test_add_auth_key() {
        let label = "test_label";
        let expiry = Some("2023-12-31T23:59:59Z".to_string());
        let endpoints = vec!["/api/v1/resource".to_string()];
        add_auth_key(label, expiry, endpoints).await;
        let keys = load_keys().await;
        let key_entry = keys.iter().find(|k| k.label == label).expect("Key entry not found");
        assert_eq!(key_entry.label, label);
        assert_eq!(key_entry.expiry.unwrap().to_rfc3339(), "2023-12-31T23:59:59+00:00");
        assert_eq!(key_entry.endpoints, vec!["/api/v1/resource".to_string()]);
    }

    #[tokio::test]
    async fn test_remove_auth_key() {
        let label = "test_label";
        let expiry = Some("2023-12-31T23:59:59Z".to_string());
        let endpoints = vec!["/api/v1/resource".to_string()];
        add_auth_key(label, expiry, endpoints).await;
        remove_auth_key(label).await;
        let keys = load_keys().await;
        let key_entry = keys.iter().find(|k| k.label == label);
        assert!(key_entry.is_none());
    }

    #[tokio::test]
    async fn test_key_exists() {
        let label = "test_label";
        let expiry = Some("2023-12-31T23:59:59Z".to_string());
        let endpoints = vec!["/api/v1/resource".to_string()];
        add_auth_key(label, expiry, endpoints).await;
        let keys = Arc::new(load_keys().await);
        let pub_key = keys.iter().find(|k| k.label == label).unwrap().pub_key.clone();
        assert!(key_exists(keys.clone(), pub_key.clone()).await);
        assert!(!key_exists(keys, "non_existent_key".to_string()).await);
    }

    #[tokio::test]
    async fn test_key_is_unexpired() {
        let label = "test_label";
        let expiry = Some((Utc::now() + chrono::Duration::days(1)).to_rfc3339());
        let endpoints = vec!["/api/v1/resource".to_string()];
        add_auth_key(label, expiry, endpoints).await;
        let keys = Arc::new(load_keys().await);
        let pub_key = keys.iter().find(|k| k.label == label).unwrap().pub_key.clone();
        assert!(key_is_unexpired(keys.clone(), pub_key.clone()).await);
    }

    #[tokio::test]
    async fn test_key_is_expired() {
        let label = "test_label";
        let expiry = Some((Utc::now() - chrono::Duration::days(1)).to_rfc3339());
        let endpoints = vec!["/api/v1/resource".to_string()];
        add_auth_key(label, expiry, endpoints).await;
        let keys = Arc::new(load_keys().await);
        let pub_key = keys.iter().find(|k| k.label == label).unwrap().pub_key.clone();
        assert!(!key_is_unexpired(keys.clone(), pub_key.clone()).await);
    }

    #[tokio::test]
    async fn test_key_no_expiry() {
        let label = "test_label";
        let endpoints = vec!["/api/v1/resource".to_string()];
        add_auth_key(label, None, endpoints).await;
        let keys = Arc::new(load_keys().await);
        let pub_key = keys.iter().find(|k| k.label == label).unwrap().pub_key.clone();
        assert!(key_is_unexpired(keys.clone(), pub_key.clone()).await);
    }
}
