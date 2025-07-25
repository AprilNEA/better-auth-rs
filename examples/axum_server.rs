use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;
use axum::{
    Router,
    extract::{Request, State},
    response::{Html, Response},
    http::StatusCode,
    routing::{get, post},
    middleware::{self, Next},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use chrono;

#[derive(Serialize, Deserialize)]
struct UserProfile {
    id: String,
    email: String,
    name: Option<String>,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct ApiResponse<T = ()> {
    success: bool,
    data: Option<T>,
    message: String,
}

impl<T> ApiResponse<T> {
    fn success(data: T, message: &str) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: message.to_string(),
        }
    }
    
    fn error(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: message.to_string(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 Starting Better Auth Axum Server");
    
    // Create configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:8080")
        .password_min_length(6);
    
    println!("📋 Configuration created");
    
    // Create database adapter (use in-memory for this example)
    let database = MemoryDatabaseAdapter::new();
    
    // Build the authentication system
    let auth = Arc::new(
        BetterAuth::new(config)
            .database(database)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .build()
            .await?
    );
    
    println!("🔐 BetterAuth instance created");
    println!("📝 Registered plugins: {:?}", auth.plugin_names());
    
    // Create the main application router
    let app = create_app_router(auth).await;
    
    println!("🌐 Starting server on http://localhost:8080");
    println!("📖 Open your browser and visit:");
    println!("   • http://localhost:8080 - Demo web interface");
    println!("   • http://localhost:8080/health - Health check");
    println!("   • http://localhost:8080/api/profile - Protected API route");
    
    // Start the server
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn create_app_router(auth: Arc<BetterAuth>) -> Router {
    // Create auth router with all authentication endpoints  
    let auth_router = Router::new()
        .route("/health", get(health_check))
        .route("/sign-up", post(auth_handler))
        .route("/sign-in", post(auth_handler))
        .with_state(auth.clone());
    
    // Create main application router
    Router::new()
        // Demo web interface
        .route("/", get(serve_demo_page))
        
        // API routes
        .route("/api/profile", get(get_user_profile))
        .route("/api/protected", get(protected_route))
        .route("/api/public", get(public_route))
        
        // Mount auth routes under /auth prefix
        .nest("/auth", auth_router)
        
        // Add middleware
        .layer(CorsLayer::permissive())
        .layer(middleware::from_fn_with_state(auth.clone(), auth_middleware))
        
        // Add the auth state
        .with_state(auth)
}

// Middleware to extract and validate session
async fn auth_middleware(
    State(_auth): State<Arc<BetterAuth>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Extract session token from Authorization header or cookie
    let token = extract_session_token(&req);
    
    if let Some(token) = token {
        // Validate session (this would be implemented in your auth system)
        // For now, just pass the token along in extensions
        req.extensions_mut().insert(token);
    }
    
    next.run(req).await
}

fn extract_session_token(req: &Request) -> Option<String> {
    // Try Authorization header first
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str[7..].to_string());
            }
        }
    }
    
    // Try session cookie
    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if cookie.starts_with("session_token=") {
                    return Some(cookie[14..].to_string());
                }
            }
        }
    }
    
    None
}

// Basic auth handler for sign-up and sign-in
async fn auth_handler(
    State(_auth): State<Arc<BetterAuth>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // This is a simplified handler - in the real implementation, 
    // this would route to the appropriate plugin handler
    Ok(Json(serde_json::json!({
        "message": "Auth endpoint - implement with BetterAuth plugin routing",
        "received": payload
    })))
}

// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "better-auth-axum-demo",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// Demo HTML page
async fn serve_demo_page() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Better Auth Demo</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #555;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e1e1;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #007bff;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        button:hover {
            background: #0056b3;
        }
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .response {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
        }
        .tab {
            flex: 1;
            padding: 12px;
            text-align: center;
            background: #e9ecef;
            border: none;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .tab.active {
            background: #007bff;
            color: white;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .endpoints {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        .endpoint {
            margin-bottom: 10px;
            font-family: monospace;
        }
        .method {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 10px;
        }
        .get { background: #28a745; color: white; }
        .post { background: #007bff; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Better Auth Demo</h1>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('signup')">Sign Up</button>
            <button class="tab" onclick="showTab('signin')">Sign In</button>
            <button class="tab" onclick="showTab('profile')">Profile</button>
        </div>
        
        <div id="signup" class="tab-content active">
            <h3>Create Account</h3>
            <form onsubmit="signUp(event)">
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" id="signup-email" required placeholder="user@example.com">
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" id="signup-password" required placeholder="Your secure password">
                </div>
                <div class="form-group">
                    <label>Name:</label>
                    <input type="text" id="signup-name" placeholder="Your display name">
                </div>
                <button type="submit">Create Account</button>
            </form>
        </div>
        
        <div id="signin" class="tab-content">
            <h3>Sign In</h3>
            <form onsubmit="signIn(event)">
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" id="signin-email" required placeholder="user@example.com">
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" id="signin-password" required placeholder="Your password">
                </div>
                <button type="submit">Sign In</button>
            </form>
        </div>
        
        <div id="profile" class="tab-content">
            <h3>User Profile</h3>
            <button onclick="getProfile()">Get My Profile</button>
            <button onclick="testProtected()">Test Protected Route</button>
            <button onclick="signOut()">Sign Out</button>
        </div>
        
        <div id="response" class="response" style="display: none;"></div>
    </div>
    
    <div class="container">
        <h2>Available Endpoints</h2>
        <div class="endpoints">
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/auth/sign-up</code> - Create new account
            </div>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/auth/sign-in</code> - Sign in to account
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/auth/health</code> - Health check
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/profile</code> - Get user profile (protected)
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/protected</code> - Protected route example
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/public</code> - Public route example
            </div>
        </div>
    </div>

    <script>
        let sessionToken = localStorage.getItem('session_token');
        
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        function showResponse(data, isError = false) {
            const responseDiv = document.getElementById('response');
            responseDiv.style.display = 'block';
            responseDiv.className = `response ${isError ? 'error' : 'success'}`;
            responseDiv.textContent = JSON.stringify(data, null, 2);
        }
        
        async function signUp(event) {
            event.preventDefault();
            const email = document.getElementById('signup-email').value;
            const password = document.getElementById('signup-password').value;
            const name = document.getElementById('signup-name').value;
            
            try {
                const response = await fetch('/auth/sign-up', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password, name })
                });
                
                const data = await response.json();
                
                if (response.ok && data.session_token) {
                    sessionToken = data.session_token;
                    localStorage.setItem('session_token', sessionToken);
                    showResponse({ success: true, message: 'Account created successfully!', user: data.user });
                    showTab('profile');
                } else {
                    showResponse(data, true);
                }
            } catch (error) {
                showResponse({ error: error.message }, true);
            }
        }
        
        async function signIn(event) {
            event.preventDefault();
            const email = document.getElementById('signin-email').value;
            const password = document.getElementById('signin-password').value;
            
            try {
                const response = await fetch('/auth/sign-in', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (response.ok && data.session_token) {
                    sessionToken = data.session_token;
                    localStorage.setItem('session_token', sessionToken);
                    showResponse({ success: true, message: 'Signed in successfully!', user: data.user });
                    showTab('profile');
                } else {
                    showResponse(data, true);
                }
            } catch (error) {
                showResponse({ error: error.message }, true);
            }
        }
        
        async function getProfile() {
            if (!sessionToken) {
                showResponse({ error: 'Please sign in first' }, true);
                return;
            }
            
            try {
                const response = await fetch('/api/profile', {
                    headers: { 'Authorization': `Bearer ${sessionToken}` }
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showResponse(data);
                } else {
                    showResponse(data, true);
                }
            } catch (error) {
                showResponse({ error: error.message }, true);
            }
        }
        
        async function testProtected() {
            if (!sessionToken) {
                showResponse({ error: 'Please sign in first' }, true);
                return;
            }
            
            try {
                const response = await fetch('/api/protected', {
                    headers: { 'Authorization': `Bearer ${sessionToken}` }
                });
                
                const data = await response.json();
                showResponse(data, !response.ok);
            } catch (error) {
                showResponse({ error: error.message }, true);
            }
        }
        
        function signOut() {
            sessionToken = null;
            localStorage.removeItem('session_token');
            showResponse({ success: true, message: 'Signed out successfully!' });
            showTab('signin');
        }
        
        // Test public route on load
        fetch('/api/public')
            .then(r => r.json())
            .then(data => console.log('Public route test:', data))
            .catch(e => console.error('Public route error:', e));
    </script>
</body>
</html>
"#)
}

// API route handlers
async fn get_user_profile(
    State(_auth): State<Arc<BetterAuth>>,
    req: Request,
) -> Result<Json<ApiResponse<UserProfile>>, StatusCode> {
    // Extract session token from request
    if let Some(_token) = req.extensions().get::<String>() {
        // In a real implementation, you'd validate the session and get user data
        let profile = UserProfile {
            id: "user_123".to_string(),
            email: "user@example.com".to_string(),
            name: Some("Test User".to_string()),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };
        
        Ok(Json(ApiResponse::success(profile, "Profile retrieved successfully")))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn protected_route(
    req: Request,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    if req.extensions().get::<String>().is_some() {
        let data = serde_json::json!({
            "message": "This is a protected route",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "server": "Better Auth Axum Server"
        });
        
        Ok(Json(ApiResponse::success(data, "Access granted to protected route")))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn public_route() -> Json<ApiResponse<serde_json::Value>> {
    let data = serde_json::json!({
        "message": "This is a public route - no authentication required",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "server": "Better Auth Axum Server",
        "endpoints": [
            "POST /auth/sign-up",
            "POST /auth/sign-in", 
            "GET /auth/health",
            "GET /api/profile (protected)",
            "GET /api/protected (protected)",
            "GET /api/public"
        ]
    });
    
    Json(ApiResponse::success(data, "Public route accessed successfully"))
} 