use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::core::{AuthPlugin, AuthRoute, AuthContext, SessionManager};
use crate::types::{AuthRequest, AuthResponse, HttpMethod, User, Session};
use crate::error::{AuthError, AuthResult};

/// Session management plugin for handling session operations
pub struct SessionManagementPlugin {
    config: SessionManagementConfig,
}

#[derive(Debug, Clone)]
pub struct SessionManagementConfig {
    pub enable_session_listing: bool,
    pub enable_session_revocation: bool,
    pub require_authentication: bool,
}

// Request structures for session endpoints
#[derive(Debug, Deserialize)]
struct RevokeSessionRequest {
    #[serde(rename = "sessionToken")]
    session_token: Option<String>,
}

// Response structures
#[derive(Debug, Serialize)]
struct GetSessionResponse {
    session: Session,
    user: User,
}

#[derive(Debug, Serialize)]
struct ListSessionsResponse {
    sessions: Vec<Session>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: bool,
}

impl SessionManagementPlugin {
    pub fn new() -> Self {
        Self {
            config: SessionManagementConfig::default(),
        }
    }
    
    pub fn with_config(config: SessionManagementConfig) -> Self {
        Self { config }
    }
    
    pub fn enable_session_listing(mut self, enable: bool) -> Self {
        self.config.enable_session_listing = enable;
        self
    }
    
    pub fn enable_session_revocation(mut self, enable: bool) -> Self {
        self.config.enable_session_revocation = enable;
        self
    }
    
    pub fn require_authentication(mut self, require: bool) -> Self {
        self.config.require_authentication = require;
        self
    }
}

impl Default for SessionManagementPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SessionManagementConfig {
    fn default() -> Self {
        Self {
            enable_session_listing: true,
            enable_session_revocation: true,
            require_authentication: true,
        }
    }
}

#[async_trait]
impl AuthPlugin for SessionManagementPlugin {
    fn name(&self) -> &'static str {
        "session-management"
    }
    
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "get_session"),
            AuthRoute::get("/list-sessions", "list_sessions"),
            AuthRoute::post("/revoke-session", "revoke_session"),
            AuthRoute::post("/revoke-sessions", "revoke_sessions"),
            AuthRoute::post("/revoke-other-sessions", "revoke_other_sessions"),
        ]
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/get-session") => {
                Ok(Some(self.handle_get_session(req, ctx).await?))
            },
            (HttpMethod::Get, "/list-sessions") if self.config.enable_session_listing => {
                Ok(Some(self.handle_list_sessions(req, ctx).await?))
            },
            (HttpMethod::Post, "/revoke-session") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_session(req, ctx).await?))
            },
            (HttpMethod::Post, "/revoke-sessions") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_sessions(req, ctx).await?))
            },
            (HttpMethod::Post, "/revoke-other-sessions") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_other_sessions(req, ctx).await?))
            },
            _ => Ok(None),
        }
    }
}

// Implementation methods outside the trait
impl SessionManagementPlugin {
    async fn handle_get_session(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user and session
        let (user, session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        let response = GetSessionResponse { session, user };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_list_sessions(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user
        let (user, _current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Get all user sessions from database (we need to implement this)
        let sessions = self.get_user_sessions(&user.id, ctx).await?;
        
        let response = ListSessionsResponse { sessions };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_revoke_session(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user to ensure they're authenticated
        let (user, _current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        let revoke_req: RevokeSessionRequest = match req.body_as_json() {
            Ok(req) => req,
            Err(e) => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Invalid request",
                    "message": format!("Invalid JSON: {}", e)
                }))?);
            }
        };
        
        // Get the session token to revoke
        let session_token = match &revoke_req.session_token {
            Some(token) => token,
            None => {
                return Ok(AuthResponse::json(400, &serde_json::json!({
                    "error": "Missing session token",
                    "message": "Session token is required"
                }))?);
            }
        };
        
        // Verify the session belongs to the current user before revoking
        let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
        if let Some(session_to_revoke) = session_manager.get_session(session_token).await? {
            if session_to_revoke.user_id != user.id {
                return Ok(AuthResponse::json(403, &serde_json::json!({
                    "error": "Forbidden",
                    "message": "Cannot revoke session that belongs to another user"
                }))?);
            }
        }
        
        // Revoke the session
        ctx.database.delete_session(session_token).await?;
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_revoke_sessions(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user to ensure they're authenticated
        let (user, _current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Revoke all sessions for the user
        ctx.database.delete_user_sessions(&user.id).await?;
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn handle_revoke_other_sessions(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<AuthResponse> {
        // Get current user and session
        let (user, current_session) = match self.get_current_user_and_session(req, ctx).await? {
            Some((user, session)) => (user, session),
            None => {
                return Ok(AuthResponse::json(401, &serde_json::json!({
                    "error": "Unauthorized",
                    "message": "No valid session found"
                }))?);
            }
        };
        
        // Get all sessions for the user
        let all_sessions = self.get_user_sessions(&user.id, ctx).await?;
        
        // Revoke all sessions except the current one
        for session in all_sessions {
            if session.token != current_session.token {
                ctx.database.delete_session(&session.token).await?;
            }
        }
        
        let response = StatusResponse { status: true };
        Ok(AuthResponse::json(200, &response)?)
    }
    
    async fn get_current_user_and_session(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<(User, Session)>> {
        // Extract session token from Authorization header
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
            let session_manager = SessionManager::new(ctx.config.clone(), ctx.database.clone());
            if let Some(session) = session_manager.get_session(token).await? {
                if let Some(user) = ctx.database.get_user_by_id(&session.user_id).await? {
                    return Ok(Some((user, session)));
                }
            }
        }
        
        Ok(None)
    }
    
    async fn get_user_sessions(&self, user_id: &str, ctx: &AuthContext) -> AuthResult<Vec<Session>> {
        ctx.database.get_user_sessions(user_id).await
    }
}