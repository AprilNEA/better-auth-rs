# Better Auth Database Migrations

This directory contains migration scripts for Better Auth PostgreSQL database.

## Quick Start

### 1. Install sqlx-cli

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

### 2. Set Environment Variables

```bash
export DATABASE_URL="postgresql://username:password@localhost:5432/better_auth"
```

### 3. Create Database

```bash
sqlx database create
```

### 4. Run Migrations

```bash
sqlx migrate run
```

## Manual Migration Execution

If you don't use sqlx-cli, you can also execute SQL scripts manually:

```bash
psql $DATABASE_URL -f migrations/001_initial.sql
```

## Database Schema

### Users Table
- `id` - User unique identifier
- `email` - User email (unique)
- `name` - User display name
- `image` - User avatar URL
- `email_verified` - Email verification status
- `created_at` - Creation time
- `updated_at` - Update time (automatically maintained)
- `metadata` - Extended data in JSON format

### Sessions Table
- `id` - Session unique identifier
- `user_id` - Associated user ID
- `token` - Session token
- `expires_at` - Expiration time
- `created_at` - Creation time
- `ip_address` - Client IP address
- `user_agent` - Client user agent
- `active` - Whether session is active

### Accounts Table (OAuth)
- `id` - Account unique identifier
- `user_id` - Associated user ID
- `provider` - OAuth provider (e.g. google, github)
- `provider_account_id` - Provider's account ID
- `access_token` - Access token
- `refresh_token` - Refresh token
- `expires_at` - Token expiration time
- `token_type` - Token type
- `scope` - Authorization scope
- `created_at` - Creation time

## Index Optimization

The script includes indexes for common queries:
- User email queries
- Session token queries
- User session queries
- OAuth account queries

## Maintenance Functions

### Clean Up Expired Sessions

```sql
SELECT cleanup_expired_sessions();
```

### View Active Sessions

```sql
SELECT * FROM active_sessions;
```

## Development Environment Setup

For development environment, you can use Docker to quickly start PostgreSQL:

```bash
docker run --name better-auth-postgres \
  -e POSTGRES_DB=better_auth \
  -e POSTGRES_USER=better_auth \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -d postgres:15
```

Then set environment variables:

```bash
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"
``` 