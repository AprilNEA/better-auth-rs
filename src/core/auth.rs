use std::sync::Arc;
use std::collections::HashMap;
use chrono;

use crate::types::{
    AuthRequest, AuthResponse, UpdateUserRequest, UpdateUserResponse, 
    DeleteUserResponse, UpdateUser, HttpMethod, User
};
use crate::error::{AuthError, AuthResult};
use crate::adapters::DatabaseAdapter;
use crate::core::{AuthConfig, AuthPlugin, AuthContext, SessionManager};

/// The main BetterAuth instance
pub struct BetterAuth {
    config: Arc<AuthConfig>,
    plugins: Vec<Box<dyn AuthPlugin>>,
    database: Arc<dyn DatabaseAdapter>,
    session_manager: SessionManager,
    context: AuthContext,
}

/// Builder for configuring BetterAuth
pub struct AuthBuilder {
    config: AuthConfig,
    plugins: Vec<Box<dyn AuthPlugin>>,
}

impl AuthBuilder {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            plugins: Vec::new(),
        }
    }
    
    /// Add a plugin to the authentication system
    pub fn plugin<P: AuthPlugin + 'static>(mut self, plugin: P) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }
    
    /// Set the database adapter
    pub fn database<D: DatabaseAdapter + 'static>(mut self, database: D) -> Self {
        self.config.database = Some(Arc::new(database));
        self
    }
    
    /// Build the BetterAuth instance
    pub async fn build(self) -> AuthResult<BetterAuth> {
        // Validate configuration
        self.config.validate()?;
        
        let config = Arc::new(self.config);
        let database = config.database.as_ref().unwrap().clone();
        
        // Create session manager
        let session_manager = SessionManager::new(config.clone(), database.clone());
        
        // Create context
        let mut context = AuthContext::new(config.clone(), database.clone());
        
        // Initialize all plugins
        for plugin in &self.plugins {
            plugin.on_init(&mut context).await?;
        }
        
        Ok(BetterAuth {
            config,
            plugins: self.plugins,
            database,
            session_manager,
            context,
        })
    }
}

impl BetterAuth {
    /// Create a new BetterAuth builder
    pub fn new(config: AuthConfig) -> AuthBuilder {
        AuthBuilder::new(config)
    }
    
    /// Handle an authentication request
    pub async fn handle_request(&self, req: AuthRequest) -> AuthResult<AuthResponse> {
        // Handle core endpoints first
        if let Some(response) = self.handle_core_request(&req).await? {
            return Ok(response);
        }
        
        // Try each plugin until one handles the request
        for plugin in &self.plugins {
            if let Some(response) = plugin.on_request(&req, &self.context).await? {
                return Ok(response);
            }
        }
        
        // No plugin handled the request
        Ok(AuthResponse::json(404, &serde_json::json!({
            "error": "Not found",
            "message": "No plugin found to handle this request"
        }))?)
    }
    
    /// Get the configuration
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }
    
    /// Get the database adapter
    pub fn database(&self) -> &Arc<dyn DatabaseAdapter> {
        &self.database
    }
    
    /// Get the session manager
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }
    
    /// Get all routes from plugins
    pub fn routes(&self) -> Vec<(String, &dyn AuthPlugin)> {
        let mut routes = Vec::new();
        for plugin in &self.plugins {
            for route in plugin.routes() {
                routes.push((route.path, plugin.as_ref()));
            }
        }
        routes
    }
    
    /// Get all plugins (useful for Axum integration)
    pub fn plugins(&self) -> &Vec<Box<dyn AuthPlugin>> {
        &self.plugins
    }
    
    /// Get plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&dyn AuthPlugin> {
        self.plugins.iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }
    
    /// List all plugin names
    pub fn plugin_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }
    
    /// Handle core authentication requests (user profile management)
    async fn handle_core_request(&self, req: &AuthRequest) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/update-user") => {
                Ok(Some(self.handle_update_user(req).await?))
            },
            (HttpMethod::Delete, "/delete-user") => {
                Ok(Some(self.handle_delete_user(req).await?))
            },
            _ => Ok(None), // Not a core endpoint
        }
    }
    
    /// Handle user profile update
    async fn handle_update_user(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        // Extract and validate session
        let current_user = self.extract_current_user(req).await?;
        
        // Parse request body
        let update_req: UpdateUserRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Convert to UpdateUser
        let update_user = UpdateUser {
            email: update_req.email,
            name: update_req.name,
            image: update_req.image,
            email_verified: None, // Don't allow changing verification status through this endpoint
            username: update_req.username,
            display_username: update_req.display_username,
            role: update_req.role,
            banned: None, // Don't allow changing banned status through this endpoint
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None, // Don't allow changing 2FA status through this endpoint
            metadata: update_req.metadata,
        };
        
        // Update user in database
        let updated_user = self.database.update_user(&current_user.id, update_user).await?;
        
        let response = UpdateUserResponse {
            user: updated_user,
        };
        
        Ok(AuthResponse::json(200, &response)?)
    }
    
    /// Handle user deletion
    async fn handle_delete_user(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        // Extract and validate session
        let current_user = self.extract_current_user(req).await?;
        
        // Delete all user sessions first
        self.database.delete_user_sessions(&current_user.id).await?;
        
        // Delete the user
        self.database.delete_user(&current_user.id).await?;
        
        let response = DeleteUserResponse {
            success: true,
            message: "User account successfully deleted".to_string(),
        };
        
        Ok(AuthResponse::json(200, &response)?)
    }
    
    /// Extract current user from request (validates session)
    async fn extract_current_user(&self, req: &AuthRequest) -> AuthResult<User> {
        // Extract token from Authorization header
        let token = self.extract_bearer_token(req)
            .ok_or_else(|| AuthError::Unauthenticated)?;
        
        // Get session from database
        let session = self.database.get_session(&token).await?
            .ok_or_else(|| AuthError::SessionNotFound)?;
        
        // Check if session is expired
        if session.expires_at < chrono::Utc::now() {
            return Err(AuthError::SessionNotFound);
        }
        
        // Get user from database
        let user = self.database.get_user_by_id(&session.user_id).await?
            .ok_or_else(|| AuthError::UserNotFound)?;
        
        Ok(user)
    }
    
    /// Extract Bearer token from Authorization header
    fn extract_bearer_token(&self, req: &AuthRequest) -> Option<String> {
        req.headers.get("authorization")
            .and_then(|auth| {
                if auth.starts_with("Bearer ") {
                    Some(auth[7..].to_string())
                } else {
                    None
                }
            })
    }
} 