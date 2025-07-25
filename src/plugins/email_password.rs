use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};

use crate::core::{AuthPlugin, AuthRoute, AuthContext};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, CreateUser, User};
use crate::error::{AuthError, AuthResult};

/// Email and password authentication plugin
pub struct EmailPasswordPlugin {
    config: EmailPasswordConfig,
}

#[derive(Debug, Clone)]
pub struct EmailPasswordConfig {
    pub enable_signup: bool,
    pub require_email_verification: bool,
    pub password_min_length: usize,
}

#[derive(Debug, Deserialize)]
struct SignUpRequest {
    email: String,
    password: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignInRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthSuccessResponse {
    user: User,
    session_token: String,
}

impl EmailPasswordPlugin {
    pub fn new() -> Self {
        Self {
            config: EmailPasswordConfig::default(),
        }
    }
    
    pub fn with_config(config: EmailPasswordConfig) -> Self {
        Self { config }
    }
    
    pub fn enable_signup(mut self, enable: bool) -> Self {
        self.config.enable_signup = enable;
        self
    }
    
    pub fn require_email_verification(mut self, require: bool) -> Self {
        self.config.require_email_verification = require;
        self
    }
    
    pub fn password_min_length(mut self, length: usize) -> Self {
        self.config.password_min_length = length;
        self
    }
    
    async fn handle_sign_up(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        if !self.config.enable_signup {
            return Ok(AuthResponse::json(403, &serde_json::json!({
                "error": "Signup disabled",
                "message": "User registration is not enabled"
            }))?);
        }
        
        let signup_req: SignUpRequest = req.body_as_json()
            .map_err(|e| AuthError::InvalidRequest(format!("Invalid JSON: {}", e)))?;
        
        // Validate password
        self.validate_password(&signup_req.password)?;
        
        // Check if user already exists
        if let Some(_) = ctx.database.get_user_by_email(&signup_req.email).await? {
            return Ok(AuthResponse::json(409, &serde_json::json!({
                "error": "User exists",
                "message": "A user with this email already exists"
            }))?);
        }
        
        // Hash password
        let password_hash = self.hash_password(&signup_req.password)?;
        
        // Create user with password hash in metadata
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));
        
        let create_user = CreateUser::new()
            .with_email(&signup_req.email)
            .with_name(signup_req.name.unwrap_or_default());
        
        let mut create_user = create_user;
        create_user.metadata = Some(metadata);
            
        let user = ctx.database.create_user(create_user).await?;
        
        // Create session
        let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;
        
        let response = AuthSuccessResponse {
            user,
            session_token: session.token,
        };
        
        Ok(AuthResponse::json(201, &response)?)
    }
    
    async fn handle_sign_in(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let signin_req: SignInRequest = req.body_as_json()
            .map_err(|e| AuthError::InvalidRequest(format!("Invalid JSON: {}", e)))?;
        
        // Get user by email
        let user = ctx.database.get_user_by_email(&signin_req.email).await?
            .ok_or(AuthError::InvalidCredentials)?;
        
        // Verify password (assuming password is stored in metadata)
        let stored_hash = user.metadata.get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;
            
        self.verify_password(&signin_req.password, stored_hash)?;
        
        // Create session
        let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
        let session = session_manager.create_session(&user, None, None).await?;
        
        let response = AuthSuccessResponse {
            user,
            session_token: session.token,
        };
        
        Ok(AuthResponse::json(200, &response)?)
    }
    
    fn validate_password(&self, password: &str) -> AuthResult<()> {
        if password.len() < self.config.password_min_length {
            return Err(AuthError::InvalidRequest(format!(
                "Password must be at least {} characters long",
                self.config.password_min_length
            )));
        }
        
        // Add more password validation rules here
        
        Ok(())
    }
    
    fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;
            
        Ok(password_hash.to_string())
    }
    
    fn verify_password(&self, password: &str, hash: &str) -> AuthResult<()> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHash(format!("Invalid password hash: {}", e)))?;
            
        let argon2 = Argon2::default();
        argon2.verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;
            
        Ok(())
    }
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enable_signup: true,
            require_email_verification: false,
            password_min_length: 8,
        }
    }
}

#[async_trait]
impl AuthPlugin for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email-password"
    }
    
    fn routes(&self) -> Vec<AuthRoute> {
        let mut routes = vec![
            AuthRoute::post("/sign-in", "sign_in"),
        ];
        
        if self.config.enable_signup {
            routes.push(AuthRoute::post("/sign-up", "sign_up"));
        }
        
        routes
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<crate::types::AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-up") if self.config.enable_signup => {
                Ok(Some(self.handle_sign_up(req, ctx).await?))
            },
            (HttpMethod::Post, "/sign-in") => {
                Ok(Some(self.handle_sign_in(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
    
    async fn on_user_created(&self, user: &User, ctx: &AuthContext) -> AuthResult<()> {
        // Could send verification email here if required
        if self.config.require_email_verification {
            // TODO: Implement email verification
            println!("TODO: Send verification email to {}", user.email.as_deref().unwrap_or("unknown"));
        }
        
        Ok(())
    }
} 