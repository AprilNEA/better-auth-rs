# Better Auth PostgreSQL Integration Guide 🐘

This guide will help you use PostgreSQL database with Better Auth Rust.

## ✨ Complete PostgreSQL Support

Better Auth now provides complete PostgreSQL support, including:

- 🗄️ **Complete Database Adapter** - Supports all CRUD operations
- 🔧 **Automatic Migration Scripts** - One-click creation of required database tables
- ⚡ **Connection Pool Optimization** - High-performance database connection management
- 🔒 **Type Safety** - Complete Rust type mapping
- 📊 **Index Optimization** - Performance optimization for common queries

## 🚀 Quick Start

### 1. Add Dependencies

Enable PostgreSQL support in your `Cargo.toml`:

```toml
[dependencies]
better-auth = { version = "0.0.1-alpha.1", features = ["sqlx-postgres"] }
```

### 2. Setup Database

Use Docker to quickly start PostgreSQL:

```bash
docker run --name better-auth-postgres \
  -e POSTGRES_DB=better_auth \
  -e POSTGRES_USER=better_auth \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -d postgres:15
```

### 3. Set Environment Variables

```bash
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"
```

### 4. Run Database Migrations

```bash
# Use provided migration scripts
psql $DATABASE_URL -f migrations/001_initial.sql

# Or use sqlx-cli (recommended)
cargo install sqlx-cli --no-default-features --features postgres
sqlx database create
sqlx migrate run
```

### 5. Use Better Auth

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::{SqlxAdapter, PoolConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    
    // Create database adapter with optimized configuration
    let pool_config = PoolConfig {
        max_connections: 20,
        min_connections: 5,
        acquire_timeout: std::time::Duration::from_secs(30),
        idle_timeout: Some(std::time::Duration::from_secs(600)),
        max_lifetime: Some(std::time::Duration::from_secs(1800)),
    };
    
    let database = SqlxAdapter::with_config(&database_url, pool_config).await?;
    
    // Test database connection
    database.test_connection().await?;
    println!("✅ Database connection successful!");
    
    let config = AuthConfig::new("your-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);
    
    let auth = BetterAuth::new(config)
        .database(database)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;
    
    println!("🔐 Better Auth ready with PostgreSQL!");
    
    Ok(())
}
```

## 📊 Database Schema

### Table Structure

#### Users Table
```sql
CREATE TABLE users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255),
    image TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
```

#### Sessions Table
```sql
CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE
);
```

#### Accounts Table (OAuth)
```sql
CREATE TABLE accounts (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(255) NOT NULL,
    provider_account_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMPTZ,
    token_type VARCHAR(255),
    scope TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_account_id)
);
```

### Performance Optimization

All tables include indexes for common queries:

```sql
-- Users table indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_metadata ON users USING GIN(metadata);

-- Sessions table indexes
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_active ON sessions(active);

-- Accounts table indexes
CREATE INDEX idx_accounts_user_id ON accounts(user_id);
CREATE INDEX idx_accounts_provider ON accounts(provider);
CREATE INDEX idx_accounts_provider_account ON accounts(provider, provider_account_id);
```

## 🔧 Connection Pool Configuration

### Default Configuration

```rust
use better_auth::adapters::PoolConfig;

let pool_config = PoolConfig::default(); // Use default configuration
```

Default settings:
- `max_connections`: 10
- `min_connections`: 0
- `acquire_timeout`: 30 seconds
- `idle_timeout`: 10 minutes
- `max_lifetime`: 30 minutes

### Custom Configuration

```rust
let pool_config = PoolConfig {
    max_connections: 50,          // Maximum connections
    min_connections: 10,          // Minimum connections
    acquire_timeout: std::time::Duration::from_secs(10),
    idle_timeout: Some(std::time::Duration::from_secs(300)),
    max_lifetime: Some(std::time::Duration::from_secs(3600)),
};

let database = SqlxAdapter::with_config(&database_url, pool_config).await?;
```

### Monitor Connection Pool Status

```rust
let stats = database.pool_stats();
println!("Pool size: {}, Idle connections: {}", stats.size, stats.idle);
```

## 🧪 Testing and Examples

### Run Complete Example

```bash
# Set database environment variable
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"

# Run PostgreSQL example
cargo run --example postgres_usage --features sqlx-postgres
```

### Example Output

```
🐘 Better Auth PostgreSQL Example
📋 Connecting to database: postgresql://better_auth:****@localhost:5432/better_auth
✅ Database connection established
🔐 BetterAuth instance created successfully!
📝 Registered plugins: ["email-password"]

🧪 Testing user registration...
✅ Registration successful: Status 201
👤 Created user: postgres_user@example.com
🆔 User ID: f4b57bed-5048-4396-bd30-0d680b97b3e1
🎫 Session token: session_b2f8cad5...

🧪 Testing user login...
✅ Login successful: Status 200
👤 Logged in user: postgres_user@example.com
📅 Account created: 2025-07-25T07:15:19.600018Z
🎫 New session token: session_0137fc07...

🎉 PostgreSQL example completed successfully!
```

## 🔍 Database Maintenance

### Clean Up Expired Sessions

Use the built-in cleanup function:

```sql
SELECT cleanup_expired_sessions();
```

### View Active Sessions

```sql
SELECT * FROM active_sessions;
```

### Backup and Restore

```bash
# Backup
pg_dump $DATABASE_URL > better_auth_backup.sql

# Restore
psql $DATABASE_URL < better_auth_backup.sql
```

## 🚨 Troubleshooting

### Common Errors

1. **Connection Failed**
   ```
   Error: connection refused
   ```
   - Ensure PostgreSQL service is running
   - Check if connection string is correct
   - Verify firewall settings

2. **Permission Error**
   ```
   Error: permission denied for table users
   ```
   - Ensure database user has sufficient permissions
   - Run migration scripts to create table structure

3. **Connection Pool Exhausted**
   ```
   Error: connection pool timed out
   ```
   - Increase `max_connections` configuration
   - Check for connection leaks
   - Adjust `acquire_timeout` time

### Performance Tuning

1. **Monitor Query Performance**
   ```sql
   -- Enable query logging
   ALTER SYSTEM SET log_statement = 'all';
   SELECT pg_reload_conf();
   ```

2. **Analyze Slow Queries**
   ```sql
   -- View slow queries
   SELECT query, mean_time, calls 
   FROM pg_stat_statements 
   ORDER BY mean_time DESC 
   LIMIT 10;
   ```

3. **Optimize Connection Pool**
   - Adjust connection count based on application load
   - Monitor connection pool metrics
   - Use appropriate timeout settings

## 📚 Additional Resources

- [PostgreSQL Official Documentation](https://www.postgresql.org/docs/)
- [SQLx Documentation](https://docs.rs/sqlx/)
- [Better Auth Source Code](https://github.com/your-repo/better-auth)

---

**Better Auth PostgreSQL** - Enterprise-grade authentication solution 🚀 