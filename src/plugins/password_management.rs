use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use uuid::Uuid;

use crate::core::{AuthPlugin, AuthRoute, AuthContext};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, User, UpdateUser, CreateVerification};
use crate::error::{AuthError, AuthResult};

/// Password management plugin for password reset and change functionality
pub struct PasswordManagementPlugin {
    config: PasswordManagementConfig,
}

#[derive(Debug, Clone)]
pub struct PasswordManagementConfig {
    pub reset_token_expiry_hours: i64,
    pub require_current_password: bool,
    pub send_email_notifications: bool,
}

// Request structures for password endpoints
#[derive(Debug, Deserialize)]
struct ForgetPasswordRequest {
    email: String,
    #[serde(rename = "redirectTo")]
    redirect_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResetPasswordRequest {
    #[serde(rename = "newPassword")]
    new_password: String,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    #[serde(rename = "newPassword")]
    new_password: String,
    #[serde(rename = "currentPassword")]
    current_password: String,
    #[serde(rename = "revokeOtherSessions")]
    revoke_other_sessions: Option<String>,
}

// Response structures
#[derive(Debug, Serialize)]
struct StatusResponse {
    status: bool,
}

#[derive(Debug, Serialize)]
struct ChangePasswordResponse {
    token: Option<String>,
    user: User,
}

impl PasswordManagementPlugin {
    pub fn new() -> Self {
        Self {
            config: PasswordManagementConfig::default(),
        }
    }
    
    pub fn with_config(config: PasswordManagementConfig) -> Self {
        Self { config }
    }
    
    pub fn reset_token_expiry_hours(mut self, hours: i64) -> Self {
        self.config.reset_token_expiry_hours = hours;
        self
    }
    
    pub fn require_current_password(mut self, require: bool) -> Self {
        self.config.require_current_password = require;
        self
    }
    
    pub fn send_email_notifications(mut self, send: bool) -> Self {
        self.config.send_email_notifications = send;
        self
    }
}

impl Default for PasswordManagementPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PasswordManagementConfig {
    fn default() -> Self {
        Self {
            reset_token_expiry_hours: 24, // 24 hours default expiry
            require_current_password: true,
            send_email_notifications: true,
        }
    }
}

#[async_trait]
impl AuthPlugin for PasswordManagementPlugin {
    fn name(&self) -> &'static str {
        "password-management"
    }
    
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/forget-password", "forget_password"),
            AuthRoute::post("/reset-password", "reset_password"),
            AuthRoute::post("/change-password", "change_password"),
        ]
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/forget-password") => {
                Ok(Some(self.handle_forget_password(req, ctx).await?))
            },
            (HttpMethod::Post, "/reset-password") => {
                Ok(Some(self.handle_reset_password(req, ctx).await?))
            },
            (HttpMethod::Post, "/change-password") => {
                Ok(Some(self.handle_change_password(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl PasswordManagementPlugin {
    async fn handle_forget_password(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let forget_req: ForgetPasswordRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Check if user exists
        let user = match ctx.database.get_user_by_email(&forget_req.email).await? {
            Some(user) => user,
            None => {
                // Don't reveal whether email exists or not for security
                let response = StatusResponse { status: true };
                return Ok(AuthResponse::json(200, &response)?);
            }
        };
        
        // Generate password reset token
        let reset_token = format!("reset_{}", Uuid::new_v4());
        let expires_at = Utc::now() + Duration::hours(self.config.reset_token_expiry_hours);
        
        // Create verification token
        let create_verification = CreateVerification {
            identifier: user.email.clone().unwrap_or_default(),
            value: reset_token.clone(),
            expires_at,
        };
        
        ctx.database.create_verification(create_verification).await?;
        
        // TODO: Send email with reset link
        // In a real implementation, you would send an email here
        if self.config.send_email_notifications {
            let reset_url = if let Some(redirect_to) = &forget_req.redirect_to {
                format!("{}?token={}", redirect_to, reset_token)
            } else {
                format!("{}/reset-password?token={}", ctx.config.base_url, reset_token)
            };
            
            println!("Password reset email would be sent to {} with URL: {}", forget_req.email, reset_url);
        }
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_reset_password(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let reset_req: ResetPasswordRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Validate password
        if let Err(e) = self.validate_password(&reset_req.new_password, ctx) {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid password",
                "message": e.to_string()
            }))?);
        }
        
        // Find user by reset token
        let token = reset_req.token.as_deref().unwrap_or("");
        if token.is_empty() {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid request",
                "message": "Reset token is required"
            }))?);
        }
        
        let (user, verification) = match self.find_user_by_reset_token(token, ctx).await? {
            Some((user, verification)) => (user, verification),
            None => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid token",
                    "message": "Invalid or expired reset token"
                }))?);
            }
        };
        
        // Hash new password
        let password_hash = self.hash_password(&reset_req.new_password)?;
        
        // Update user password
        let mut metadata = user.metadata.clone();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));
        
        let update_user = UpdateUser {
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: Some(metadata),
        };
        
        ctx.database.update_user(&user.id, update_user).await?;
        
        // Delete the used verification token
        ctx.database.delete_verification(&verification.id).await?;
        
        // Revoke all existing sessions for security
        ctx.database.delete_user_sessions(&user.id).await?;
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_change_password(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        let change_req: ChangePasswordRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Get current user from session (this would normally be extracted from auth middleware)
        // For now, we'll extract from Authorization header or session
        let user = match self.get_current_user(req, ctx).await? {
            Some(user) => user,
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Verify current password
        if self.config.require_current_password {
            let stored_hash = match user.metadata.get("password_hash").and_then(|v| v.as_str()) {
                Some(hash) => hash,
                None => {
                    return Ok(AuthResponse::json(400, &serde_json::json!({
                        "error": "Invalid request",
                        "message": "No password set for this user"
                    }))?);
                }
            };
            
            if let Err(_) = self.verify_password(&change_req.current_password, stored_hash) {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid password",
                    "message": "Current password is incorrect"
                }))?);
            }
        }
        
        // Validate new password
        if let Err(e) = self.validate_password(&change_req.new_password, ctx) {
            return Ok(AuthResponse::json(400, &serde_json::json!({
                "error": "Invalid password",
                "message": e.to_string()
            }))?);
        }
        
        // Hash new password
        let password_hash = self.hash_password(&change_req.new_password)?;
        
        // Update user password
        let mut metadata = user.metadata.clone();
        metadata.insert("password_hash".to_string(), serde_json::Value::String(password_hash));
        
        let update_user = UpdateUser {
            email: None,
            name: None,
            image: None,
            email_verified: None,
            username: None,
            display_username: None,
            role: None,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: Some(metadata),
        };
        
        let updated_user = ctx.database.update_user(&user.id, update_user).await?;
        
        // Handle session revocation
        let new_token = if change_req.revoke_other_sessions.as_deref() == Some("true") {
            // Revoke all sessions except current one
            ctx.database.delete_user_sessions(&user.id).await?;
            
            // Create new session
            let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
            let session = session_manager.create_session(&updated_user, None, None).await?;
            Some(session.token)
        } else {
            None
        };
        
        let response = ChangePasswordResponse {
            token: new_token,
            user: updated_user,
        };
        
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn find_user_by_reset_token(&self, token: &str, ctx: &AuthContext) -> AuthResult<Option<(User, crate::types::Verification)>> {
        // Find verification token by value
        let verification = match ctx.database.get_verification_by_value(token).await? {
            Some(verification) => verification,
            None => return Ok(None),
        };
        
        // Get user by email (stored in identifier field)
        let user = match ctx.database.get_user_by_email(&verification.identifier).await? {
            Some(user) => user,
            None => return Ok(None),
        };
        
        Ok(Some((user, verification)))
    }
    
    async fn get_current_user(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<User>> {
        // Extract session token from Authorization header or cookies
        let token = if let Some(auth_header) = req.headers.get("authorization") {
            if auth_header.starts_with("Bearer ") {
                Some(&auth_header[7..])
            } else {
                None
            }
        } else {
            None
        };
        
        if let Some(token) = token {
            let session_manager = crate::core::SessionManager::new(ctx.config.clone(), ctx.database.clone());
            if let Some(session) = session_manager.get_session(token).await? {
                return ctx.database.get_user_by_id(&session.user_id).await;
            }
        }
        
        Ok(None)
    }
    
    fn validate_password(&self, password: &str, ctx: &AuthContext) -> AuthResult<()> {
        if password.len() < ctx.config.password.min_length {
            return Err(AuthError::InvalidRequest(format!(
                "Password must be at least {} characters long",
                ctx.config.password.min_length
            )));
        }
        
        // Add more password validation rules here
        // - Must contain uppercase letter
        // - Must contain lowercase letter  
        // - Must contain number
        // - Must contain special character
        // etc.
        
        Ok(())
    }
    
    fn hash_password(&self, password: &str) -> AuthResult<String> {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::{SaltString, rand_core::OsRng};
        
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHash(format!("Failed to hash password: {}", e)))?;
            
        Ok(password_hash.to_string())
    }
    
    fn verify_password(&self, password: &str, hash: &str) -> AuthResult<()> {
        use argon2::{Argon2, PasswordVerifier};
        use argon2::password_hash::PasswordHash;
        
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHash(format!("Invalid password hash: {}", e)))?;
            
        let argon2 = Argon2::default();
        argon2.verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;
            
        Ok(())
    }
}