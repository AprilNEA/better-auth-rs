use async_trait::async_trait;

use crate::core::{AuthPlugin, AuthRoute, AuthContext};
use crate::types::{AuthRequest, AuthResponse, HttpMethod};
use crate::error::{AuthError, AuthResult};

/// OAuth authentication plugin
pub struct OAuthPlugin {
    // TODO: Add OAuth configuration
}

impl OAuthPlugin {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for OAuthPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthPlugin for OAuthPlugin {
    fn name(&self) -> &'static str {
        "oauth"
    }
    
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/oauth/{provider}", "oauth_redirect"),
            AuthRoute::get("/oauth/{provider}/callback", "oauth_callback"),
        ]
    }
    
    async fn on_request(&self, req: &AuthRequest, ctx: &AuthContext) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, path) if path.starts_with("/oauth/") => {
                // TODO: Implement OAuth flows
                Ok(Some(AuthResponse::json(501, &serde_json::json!({
                    "error": "Not implemented",
                    "message": "OAuth plugin not yet implemented"
                }))?))
            },
            _ => Ok(None),
        }
    }
} 