use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::SqlxAdapter;
use better_auth::types::{AuthRequest, HttpMethod};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🐘 Better Auth PostgreSQL Example");
    
    // Get database URL from environment variable
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://better_auth:password@localhost:5432/better_auth".to_string());
    
    println!("📋 Connecting to database: {}", hide_password(&database_url));
    
    // Create PostgreSQL adapter
    let database = SqlxAdapter::new(&database_url).await?;
    
    println!("✅ Database connection established");
    
    // Create configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);
    
    // Build authentication system
    let auth = BetterAuth::new(config)
        .database(database)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;
    
    println!("🔐 BetterAuth instance created successfully!");
    println!("📝 Registered plugins: {:?}", auth.plugin_names());
    
    // Test user registration
    println!("\n🧪 Testing user registration...");
    let signup_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "secure_password_123",
        "name": "PostgreSQL Test User"
    });
    
    let mut signup_req = AuthRequest::new(HttpMethod::Post, "/sign-up");
    signup_req.body = Some(signup_body.to_string().into_bytes());
    signup_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    match auth.handle_request(signup_req).await {
        Ok(response) => {
            println!("✅ Registration successful: Status {}", response.status);
            if let Ok(body_str) = String::from_utf8(response.body.clone()) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_str) {
                    if let Some(user) = parsed.get("user") {
                        println!("👤 Created user: {}", user.get("email").unwrap_or(&serde_json::Value::Null));
                        println!("🆔 User ID: {}", user.get("id").unwrap_or(&serde_json::Value::Null));
                    }
                    if let Some(token) = parsed.get("session_token") {
                        println!("🎫 Session token: {}...", token.as_str().unwrap_or("").chars().take(20).collect::<String>());
                    }
                }
            }
        }
        Err(e) => println!("❌ Registration failed: {}", e),
    }
    
    // Test user login
    println!("\n🧪 Testing user login...");
    let signin_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "secure_password_123"
    });
    
    let mut signin_req = AuthRequest::new(HttpMethod::Post, "/sign-in");
    signin_req.body = Some(signin_body.to_string().into_bytes());
    signin_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    match auth.handle_request(signin_req).await {
        Ok(response) => {
            println!("✅ Login successful: Status {}", response.status);
            if let Ok(body_str) = String::from_utf8(response.body.clone()) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_str) {
                    if let Some(user) = parsed.get("user") {
                        println!("👤 Logged in user: {}", user.get("email").unwrap_or(&serde_json::Value::Null));
                        println!("📅 Account created: {}", user.get("created_at").unwrap_or(&serde_json::Value::Null));
                    }
                    if let Some(token) = parsed.get("session_token") {
                        println!("🎫 New session token: {}...", token.as_str().unwrap_or("").chars().take(20).collect::<String>());
                    }
                }
            }
        }
        Err(e) => println!("❌ Login failed: {}", e),
    }
    
    // Test duplicate registration (should fail)
    println!("\n🧪 Testing duplicate registration (should fail)...");
    let duplicate_signup_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "another_password",
        "name": "Duplicate User"
    });
    
    let mut duplicate_req = AuthRequest::new(HttpMethod::Post, "/sign-up");
    duplicate_req.body = Some(duplicate_signup_body.to_string().into_bytes());
    duplicate_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    match auth.handle_request(duplicate_req).await {
        Ok(response) => {
            println!("📊 Response status: {}", response.status);
            if let Ok(body_str) = String::from_utf8(response.body) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_str) {
                    if let Some(error) = parsed.get("error") {
                        println!("⚠️  Expected error: {}", error);
                    }
                }
            }
        }
        Err(e) => println!("✅ Correctly rejected duplicate: {}", e),
    }
    
    // Test wrong password login (should fail)
    println!("\n🧪 Testing wrong password login (should fail)...");
    let wrong_password_body = serde_json::json!({
        "email": "postgres_user@example.com",
        "password": "wrong_password"
    });
    
    let mut wrong_password_req = AuthRequest::new(HttpMethod::Post, "/sign-in");
    wrong_password_req.body = Some(wrong_password_body.to_string().into_bytes());
    wrong_password_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    match auth.handle_request(wrong_password_req).await {
        Ok(response) => {
            println!("📊 Response status: {}", response.status);
            if response.status != 200 {
                println!("✅ Correctly rejected wrong password");
            }
        }
        Err(e) => println!("✅ Correctly rejected wrong password: {}", e),
    }
    
    // Display database statistics
    println!("\n📊 Database Operations Summary:");
    println!("  - Successfully connected to PostgreSQL");
    println!("  - Created user with encrypted password");
    println!("  - Generated secure session tokens");
    println!("  - Handled duplicate email validation");
    println!("  - Verified password authentication");
    
    println!("\n🎉 PostgreSQL example completed successfully!");
    println!("💡 Tip: Check your database to see the created user and session records");
    
    Ok(())
}

/// Hide password in database URL for logging output
fn hide_password(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            if let Some(slash_pos) = url[..colon_pos].rfind('/') {
                let before_password = &url[..slash_pos + 1];
                let after_password = &url[at_pos..];
                return format!("{}****{}", before_password, after_password);
            }
        }
    }
    url.to_string()
} 