use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::{EmailPasswordPlugin, PasswordManagementPlugin, EmailVerificationPlugin, SessionManagementPlugin};
use better_auth::adapters::MemoryDatabaseAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting Better Auth Rust Example");
    
    // Create configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);
    
    println!("📋 Configuration created");
    
    // Create database adapter (in-memory for this example)
    let database = MemoryDatabaseAdapter::new();
    
    // Build the authentication system
    let auth = BetterAuth::new(config)
        .database(database)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(PasswordManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await?;
    
    println!("🔐 BetterAuth instance created successfully!");
    println!("📝 Registered plugins: {:?}", auth.plugin_names());
    
    // Simulate some authentication requests
    use better_auth::types::{AuthRequest, HttpMethod};
    use std::collections::HashMap;
    
    // Test sign up
    println!("\n🧪 Testing sign up...");
    let signup_body = serde_json::json!({
        "email": "test@example.com",
        "password": "password123",
        "name": "Test User"
    });
    
    let mut signup_req = AuthRequest::new(HttpMethod::Post, "/sign-up");
    signup_req.body = Some(signup_body.to_string().into_bytes());
    signup_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    match auth.handle_request(signup_req).await {
        Ok(response) => {
            println!("✅ Sign up response: {}", response.status);
            if let Ok(body_str) = String::from_utf8(response.body) {
                println!("📄 Response body: {}", body_str);
            }
        }
        Err(e) => println!("❌ Sign up error: {}", e),
    }
    
    // Test sign in
    println!("\n🧪 Testing sign in...");
    let signin_body = serde_json::json!({
        "email": "test@example.com",
        "password": "password123"
    });
    
    let mut signin_req = AuthRequest::new(HttpMethod::Post, "/sign-in");
    signin_req.body = Some(signin_body.to_string().into_bytes());
    signin_req.headers.insert("content-type".to_string(), "application/json".to_string());
    
    match auth.handle_request(signin_req).await {
        Ok(response) => {
            println!("✅ Sign in response: {}", response.status);
            if let Ok(body_str) = String::from_utf8(response.body) {
                println!("📄 Response body: {}", body_str);
            }
        }
        Err(e) => println!("❌ Sign in error: {}", e),
    }
    
    // Test invalid route
    println!("\n🧪 Testing invalid route...");
    let invalid_req = AuthRequest::new(HttpMethod::Get, "/invalid-route");
    
    match auth.handle_request(invalid_req).await {
        Ok(response) => {
            println!("✅ Invalid route response: {}", response.status);
            if let Ok(body_str) = String::from_utf8(response.body) {
                println!("📄 Response body: {}", body_str);
            }
        }
        Err(e) => println!("❌ Invalid route error: {}", e),
    }
    
    println!("\n🎉 Example completed successfully!");
    
    Ok(())
} 