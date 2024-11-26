use crate::auth;
use crate::config::load_config;
use dialoguer::{Input, MultiSelect, Confirm};
use std::sync::Arc;

/// Command: Generates a new API key with an optional label and expiry date. Adds it to the configuration file.
/// 
/// # Arguments
/// 
/// * `label` - An optional `String` that represents the label for the API key. If not provided, the user will be prompted to enter one.
/// * `expiry` - An optional `String` that represents the expiry date for the API key in ISO 8601 format. If not provided, the user will be prompted to set one.
/// 
/// # Example
/// 
/// ```
/// use crate::commands::keys::generate_key;
/// 
/// // Generate a key with a label and expiry
/// generate_key(Some("my-label".to_string()), Some("2024-12-31T23:59:59Z".to_string())).await;
/// 
/// // Generate a key with user prompts for label and expiry
/// generate_key(None, None).await;
/// ```
pub async fn generate_key(label: Option<String>, expiry: Option<String>) {
    let config = Arc::new(load_config().await);

    let label = label.unwrap_or_else(|| {
        Input::new()
            .with_prompt("Enter a label for the API key")
            .interact_text()
            .expect("Failed to read label")
    });

    let expiry = expiry.or_else(|| {
        if Confirm::new()
            .with_prompt("Do you want to set an expiry for this key?")
            .interact()
            .expect("Failed to confirm expiry prompt")
        {
            Some(
                Input::new()
                    .with_prompt("Enter an expiry date (ISO 8601 format, e.g., 2024-12-31T23:59:59Z)")
                    .validate_with(|input: &String| {
                        chrono::DateTime::parse_from_rfc3339(input)
                            .map(|_| ())
                            .map_err(|_| "Invalid expiry format")
                    })
                    .interact_text()
                    .expect("Failed to read expiry date"),
            )
        } else {
            None
        }
    });

    let items: Vec<&String> = config.endpoints.keys().collect();
    let endpoints = MultiSelect::new()
        .with_prompt("Select allowed endpoints")
        .items(&items)
        .interact()
        .expect("Failed to select endpoints");

    let endpoints: Vec<String> = endpoints.iter().map(|&i| items[i].to_string()).collect();

    auth::generate_auth_keys(&label, expiry, endpoints).await;
}
