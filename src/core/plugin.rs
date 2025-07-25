use async_trait::async_trait;
use std::sync::Arc;
use std::collections::HashMap;

use crate::types::{AuthRequest, AuthResponse, User, Session, HttpMethod};
use crate::error::{AuthError, AuthResult};
use crate::adapters::DatabaseAdapter;
use crate::core::config::AuthConfig;

/// Plugin trait that all authentication plugins must implement
#[async_trait]
pub trait AuthPlugin: Send + Sync {
    /// Plugin name - should be unique
    fn name(&self) -> &'static str;
    
    /// Routes that this plugin handles
    fn routes(&self) -> Vec<AuthRoute>;
    
    /// Called when the plugin is initialized
    async fn on_init(&self, ctx: &mut AuthContext) -> AuthResult<()> {
        let _ = ctx;
        Ok(())
    }
    
    /// Called for each request - return Some(response) to handle, None to pass through
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>>;
    
    /// Called after a user is created
    async fn on_user_created(&self, user: &User, ctx: &AuthContext) -> AuthResult<()> {
        let _ = (user, ctx);
        Ok(())
    }
    
    /// Called after a session is created
    async fn on_session_created(&self, session: &Session, ctx: &AuthContext) -> AuthResult<()> {
        let _ = (session, ctx);
        Ok(())
    }
    
    /// Called before a user is deleted
    async fn on_user_deleted(&self, user_id: &str, ctx: &AuthContext) -> AuthResult<()> {
        let _ = (user_id, ctx);
        Ok(())
    }
    
    /// Called before a session is deleted
    async fn on_session_deleted(&self, session_token: &str, ctx: &AuthContext) -> AuthResult<()> {
        let _ = (session_token, ctx);
        Ok(())
    }
}

/// Route definition for plugins
#[derive(Debug, Clone)]
pub struct AuthRoute {
    pub path: String,
    pub method: HttpMethod,
    pub handler: String,
}

/// Context passed to plugin methods
pub struct AuthContext {
    pub config: Arc<AuthConfig>,
    pub database: Arc<dyn DatabaseAdapter>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuthRoute {
    pub fn new(method: HttpMethod, path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            method,
            handler: handler.into(),
        }
    }
    
    pub fn get(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, path, handler)
    }
    
    pub fn post(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, path, handler)
    }
    
    pub fn put(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Put, path, handler)
    }
    
    pub fn delete(path: impl Into<String>, handler: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, path, handler)
    }
}

impl AuthContext {
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn DatabaseAdapter>) -> Self {
        Self {
            config,
            database,
            metadata: HashMap::new(),
        }
    }
    
    pub fn set_metadata(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.metadata.insert(key.into(), value);
    }
    
    pub fn get_metadata(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }
} 