use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use rand::Rng;

use crate::types::{Session, CreateSession, User};
use crate::error::{AuthError, AuthResult};
use crate::adapters::DatabaseAdapter;
use crate::core::config::AuthConfig;

/// Session manager handles session creation, validation, and cleanup
pub struct SessionManager {
    config: Arc<AuthConfig>,
    database: Arc<dyn DatabaseAdapter>,
}

impl SessionManager {
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn DatabaseAdapter>) -> Self {
        Self { config, database }
    }
    
    /// Create a new session for a user
    pub async fn create_session(&self, user: &User, ip_address: Option<String>, user_agent: Option<String>) -> AuthResult<Session> {
        let token = self.generate_session_token();
        let expires_at = Utc::now() + self.config.session.expires_in;
        
        let create_session = CreateSession {
            user_id: user.id.clone(),
            expires_at,
            ip_address,
            user_agent,
            impersonated_by: None,
            active_organization_id: None,
        };
        
        let session = self.database.create_session(create_session).await?;
        Ok(session)
    }
    
    /// Get session by token
    pub async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        let session = self.database.get_session(token).await?;
        
        // Check if session exists and is not expired
        if let Some(ref session) = session {
            if session.expires_at < Utc::now() || !session.active {
                // Session expired or inactive - delete it
                self.database.delete_session(token).await?;
                return Ok(None);
            }
            
            // Update session if configured to do so
            if self.config.session.update_age {
                let new_expires_at = Utc::now() + self.config.session.expires_in;
                let _ = self.database.update_session_expiry(token, new_expires_at).await;
            }
        }
        
        Ok(session)
    }
    
    /// Delete a session
    pub async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.database.delete_session(token).await?;
        Ok(())
    }
    
    /// Delete all sessions for a user
    pub async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.database.delete_user_sessions(user_id).await?;
        Ok(())
    }
    
    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> AuthResult<usize> {
        let count = self.database.delete_expired_sessions().await?;
        Ok(count)
    }
    
    /// Generate a secure session token
    fn generate_session_token(&self) -> String {
        use rand::RngCore;
        use base64::Engine;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        format!("session_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
    
    /// Validate session token format
    pub fn validate_token_format(&self, token: &str) -> bool {
        token.starts_with("session_") && token.len() > 40
    }
} 