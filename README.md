# Better Auth - Rust 🔐

A Rust authentication framework inspired by [Better-Auth](https://www.better-auth.com/), providing a plugin-based architecture and type-safe authentication solutions.

## ✨ Features

- 🔌 **Plugin Architecture** - Easily extend and customize authentication flows
- 🛡️ **Type Safety** - Leverage Rust's type system to ensure code safety
- ⚡ **Async Support** - Full support for asynchronous operations
- 🗄️ **Database Agnostic** - Support for multiple databases through adapter pattern
- 🌐 **Web Framework Integration** - Support for Axum (extensible to other frameworks)
- 🔑 **Multiple Authentication Methods** - Email/password, OAuth, two-factor authentication, etc.

## 🚀 Quick Start

### Basic Usage

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);
    
    // Create authentication system
    let auth = BetterAuth::new(config)
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;
    
    println!("🔐 Authentication system ready!");
    println!("Registered plugins: {:?}", auth.plugin_names());
    
    Ok(())
}
```

### Axum Integration

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;
use better_auth::handlers::AxumIntegration;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AuthConfig::new("your-secret-key");
    
    let auth = Arc::new(
        BetterAuth::new(config)
            .database(MemoryDatabaseAdapter::new())
            .plugin(EmailPasswordPlugin::new())
            .build()
            .await?
    );
    
    // Create Axum router
    let app = auth.axum_router();
    
    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

## 🏗️ Architecture Design

### Core Components

- **BetterAuth** - Main authentication instance
- **AuthPlugin** - Plugin system abstraction
- **DatabaseAdapter** - Database adapter abstraction
- **AuthConfig** - Configuration management

### Plugin System

- **EmailPasswordPlugin** - Email/password authentication ✅
- **OAuthPlugin** - OAuth authentication 🚧
- **TwoFactorPlugin** - Two-factor authentication 🚧

### Database Adapters

- **MemoryDatabaseAdapter** - In-memory database (development/testing) ✅
- **SqlxAdapter** - Full PostgreSQL support ✅
  - Connection pool optimization
  - Automatic migration scripts
  - Type-safe mapping
  - Performance-optimized indexes

## 📁 Project Structure

```
better-auth/
├── src/
│   ├── core/           # Core functionality
│   │   ├── auth.rs     # Main authentication logic
│   │   ├── config.rs   # Configuration management
│   │   ├── plugin.rs   # Plugin abstraction
│   │   └── session.rs  # Session management
│   ├── plugins/        # Authentication plugins
│   │   ├── email_password.rs
│   │   ├── oauth.rs
│   │   └── two_factor.rs
│   ├── adapters/       # Database and cache adapters
│   │   ├── database.rs
│   │   └── cache.rs
│   ├── handlers/       # Web framework integration
│   │   └── axum.rs
│   ├── error.rs        # Error types
│   └── types.rs        # Core type definitions
└── examples/
    ├── basic_usage.rs     # Basic authentication example
    ├── postgres_usage.rs  # PostgreSQL database example
    └── axum_server.rs     # Complete web server with demo UI
```

## 🔧 Available Features

### Authentication Endpoints

- `POST /sign-up` - User registration
- `POST /sign-in` - User login
- `GET /health` - Health check

### Feature Flags

```toml
[features]
default = []
axum = ["dep:axum", "dep:tower", "dep:tower-http"]
sqlx-postgres = ["dep:sqlx"]
redis-cache = ["dep:redis"]
```

## 🧪 Running Examples

### Basic Usage Example
```bash
# Run basic example (in-memory database)
cargo run --example basic_usage
```

### PostgreSQL Example
```bash
# Run PostgreSQL example
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"
cargo run --example postgres_usage --features sqlx-postgres
```

### Axum Web Server Example
```bash
# Run Axum web server with interactive demo
cargo run --example axum_server --features axum
```

Then visit:
- **http://localhost:8080** - Interactive web demo with sign-up/sign-in forms
- **http://localhost:8080/auth/health** - Health check endpoint
- **http://localhost:8080/api/public** - Public API endpoint
- **http://localhost:8080/api/protected** - Protected API endpoint (requires authentication)

### Testing Compilation
```bash
# Test basic compilation
cargo check

# Test PostgreSQL features
cargo check --features sqlx-postgres

# Test Axum features
cargo check --features axum
```

## 🛠️ Development Status

### ✅ Completed
- [x] Core architecture design
- [x] Plugin system implementation
- [x] Email/password authentication
- [x] In-memory database adapter
- [x] Session management
- [x] Axum integration
- [x] Basic examples

### ✅ Recently Completed
- [x] **PostgreSQL Database Support** - Complete SQLx adapter with connection pool optimization
- [x] **Database Migration Scripts** - Automated table structure creation
- [x] **Type-Safe Mapping** - Perfect integration between PostgreSQL and Rust types
- [x] **Performance-Optimized Indexes** - Database optimization for common queries

### 🚧 In Progress
- [ ] OAuth plugin implementation
- [ ] Two-factor authentication
- [ ] Redis cache support
- [ ] More web framework integrations

## 🤝 Contributing

Contributions are welcome! Please check the project structure and existing implementations to understand how to add new features.

## 📄 License

MIT License

---

**Better Auth Rust** - Build secure, scalable authentication systems 🚀 