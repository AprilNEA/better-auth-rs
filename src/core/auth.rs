use std::sync::Arc;
use std::collections::HashMap;

use crate::types::{AuthRequest, AuthResponse};
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
} 