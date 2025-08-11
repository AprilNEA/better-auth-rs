# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The orignal prompt is from: https://www.dzombak.com/blog/2025/08/getting-good-results-from-claude-code/

# Development Guidelines

## Philosophy

### Core Beliefs

- **Incremental progress over big bangs** - Small changes that compile and pass tests
- **Learning from existing code** - Study and plan before implementing
- **Pragmatic over dogmatic** - Adapt to project reality
- **Clear intent over clever code** - Be boring and obvious

### Simplicity Means

- Single responsibility per function/class
- Avoid premature abstractions
- No clever tricks - choose the boring solution
- If you need to explain it, it's too complex

## Process

### 1. Planning & Staging

Break complex work into 3-5 stages. Document in `IMPLEMENTATION_PLAN.md`:

```markdown
## Stage N: [Name]
**Goal**: [Specific deliverable]
**Success Criteria**: [Testable outcomes]
**Tests**: [Specific test cases]
**Status**: [Not Started|In Progress|Complete]
```
- Update status as you progress
- Remove file when all stages are done

### 2. Implementation Flow

1. **Understand** - Study existing patterns in codebase
2. **Test** - Write test first (red)
3. **Implement** - Minimal code to pass (green)
4. **Refactor** - Clean up with tests passing
5. **Commit** - With clear message linking to plan

### 3. When Stuck (After 3 Attempts)

**CRITICAL**: Maximum 3 attempts per issue, then STOP.

1. **Document what failed**:
   - What you tried
   - Specific error messages
   - Why you think it failed

2. **Research alternatives**:
   - Find 2-3 similar implementations
   - Note different approaches used

3. **Question fundamentals**:
   - Is this the right abstraction level?
   - Can this be split into smaller problems?
   - Is there a simpler approach entirely?

4. **Try different angle**:
   - Different library/framework feature?
   - Different architectural pattern?
   - Remove abstraction instead of adding?

## Technical Standards

### Architecture Principles

- **Composition over inheritance** - Use dependency injection
- **Interfaces over singletons** - Enable testing and flexibility
- **Explicit over implicit** - Clear data flow and dependencies
- **Test-driven when possible** - Never disable tests, fix them

### Code Quality

- **Every commit must**:
  - Compile successfully
  - Pass all existing tests
  - Include tests for new functionality
  - Follow project formatting/linting

- **Before committing**:
  - Run formatters/linters
  - Self-review changes
  - Ensure commit message explains "why"

### Error Handling

- Fail fast with descriptive messages
- Include context for debugging
- Handle errors at appropriate level
- Never silently swallow exceptions

## Decision Framework

When multiple valid approaches exist, choose based on:

1. **Testability** - Can I easily test this?
2. **Readability** - Will someone understand this in 6 months?
3. **Consistency** - Does this match project patterns?
4. **Simplicity** - Is this the simplest solution that works?
5. **Reversibility** - How hard to change later?

## Project Integration

### Learning the Codebase

- Find 3 similar features/components
- Identify common patterns and conventions
- Use same libraries/utilities when possible
- Follow existing test patterns

### Tooling

- Use project's existing build system
- Use project's test framework
- Use project's formatter/linter settings
- Don't introduce new tools without strong justification

## Quality Gates

### Definition of Done

- [ ] Tests written and passing
- [ ] Code follows project conventions
- [ ] No linter/formatter warnings
- [ ] Commit messages are clear
- [ ] Implementation matches plan
- [ ] No TODOs without issue numbers

### Test Guidelines

- Test behavior, not implementation
- One assertion per test when possible
- Clear test names describing scenario
- Use existing test utilities/helpers
- Tests should be deterministic

## Important Reminders

**NEVER**:
- Use `--no-verify` to bypass commit hooks
- Disable tests instead of fixing them
- Commit code that doesn't compile
- Make assumptions - verify with existing code

**ALWAYS**:
- Commit working code incrementally
- Update plan documentation as you go
- Learn from existing implementations
- Stop after 3 failed attempts and reassess

## Project Overview

Better Auth is a comprehensive authentication framework for Rust, inspired by Better-Auth. It provides a plugin-based architecture with type-safe authentication solutions including email/password, OAuth, two-factor authentication, and session management.

## Common Development Commands

### Building and Testing
```bash
# Basic compilation check
cargo check

# Build the project
cargo build

# Run tests (Note: integration tests are currently disabled due to Service trait issues)
cargo test

# Run specific test
cargo test test_name

# Check with specific features
cargo check --features sqlx-postgres
cargo check --features axum
cargo check --features redis-cache

# Run tests with PostgreSQL features (requires TEST_DATABASE_URL)
export TEST_DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth_test"
cargo test --features sqlx-postgres
```

### Running Examples
```bash
# Basic usage example (in-memory database)
cargo run --example basic_usage

# PostgreSQL example (requires DATABASE_URL)
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"
cargo run --example postgres_usage --features sqlx-postgres

# Axum web server example with interactive demo
cargo run --example axum_server --features axum
```

### Database Setup (PostgreSQL)
```bash
# Start PostgreSQL with Docker
docker run --name better-auth-postgres \
  -e POSTGRES_DB=better_auth \
  -e POSTGRES_USER=better_auth \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -d postgres:15

# Run migrations
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"
psql $DATABASE_URL -f migrations/001_initial.sql

# Or using sqlx-cli
cargo install sqlx-cli --no-default-features --features postgres
sqlx database create
sqlx migrate run
```

## Architecture

### Core Components
- **BetterAuth** (`src/core/auth.rs`): Main authentication instance with builder pattern
- **AuthConfig** (`src/core/config.rs`): Configuration management
- **AuthPlugin** (`src/core/plugin.rs`): Plugin system abstraction
- **SessionManager** (`src/core/session.rs`): Session lifecycle management

### Plugin System
Located in `src/plugins/`:
- **EmailPasswordPlugin** (`email_password.rs`): Email/password authentication ✅
- **EmailVerificationPlugin** (`email_verification.rs`): Email verification workflows 🚧
- **PasswordManagementPlugin** (`password_management.rs`): Password reset and change 🚧
- **SessionManagementPlugin** (`session_management.rs`): Advanced session controls 🚧
- **OAuthPlugin** (`oauth.rs`): OAuth authentication 🚧
- **TwoFactorPlugin** (`two_factor.rs`): Two-factor authentication 🚧

### Database Adapters
Located in `src/adapters/`:
- **MemoryDatabaseAdapter**: In-memory storage for development/testing
- **SqlxAdapter**: PostgreSQL support with connection pooling and migrations
- **Cache adapters**: Redis support (planned)

### Web Framework Integration
Located in `src/handlers/`:
- **AxumIntegration** (`axum.rs`): Axum web framework support with route generation

### Feature Flags
- `axum`: Enables Axum web framework integration
- `sqlx-postgres`: Enables PostgreSQL database support via SQLx
- `redis-cache`: Enables Redis caching (planned)

## Key Patterns

### Builder Pattern Usage
The framework uses the builder pattern extensively:
```rust
let auth = BetterAuth::new(config)
    .database(SqlxAdapter::new(&database_url).await?)
    .plugin(EmailPasswordPlugin::new().enable_signup(true))
    .build()
    .await?;
```

### Plugin Architecture
Plugins implement the `AuthPlugin` trait and register handlers:
```rust
impl AuthPlugin for EmailPasswordPlugin {
    fn name(&self) -> &str { "email-password" }
    fn setup_routes(&self, router: Router) -> Router { /* ... */ }
}
```

### Database Abstraction
All database operations go through the `DatabaseAdapter` trait, allowing different storage backends while maintaining type safety.

## Important Files

### Configuration Files
- `Cargo.toml`: Dependencies and feature flags
- `migrations/001_initial.sql`: Database schema
- `migrations/README.md`: Migration instructions

### Documentation
- `README.md`: Project overview and usage examples
- `docs/POSTGRESQL_GUIDE.md`: Comprehensive PostgreSQL setup and usage guide

### Examples
- `examples/basic_usage.rs`: Simple in-memory authentication
- `examples/postgres_usage.rs`: PostgreSQL integration example
- `examples/axum_server.rs`: Complete web server with demo UI

## Development Notes

### Technical Details
- All database operations are async and use connection pooling
- The framework prioritizes type safety and compile-time error checking
- Session tokens use JWT with configurable expiration
- Password hashing uses Argon2 for security
- Database schema includes performance-optimized indexes for common queries
- The plugin system allows extending authentication methods without modifying core code

### Current Development Status
- Integration tests are temporarily disabled due to Axum Service trait issues
- PostgreSQL tests require `TEST_DATABASE_URL` environment variable
- Tests include comprehensive coverage for memory and PostgreSQL adapters
- Concurrent request handling is tested for performance validation

### Database Migration System
- Uses sqlx-cli for PostgreSQL migration management
- Manual SQL execution supported via `psql` commands
- Includes optimization functions for session cleanup
- Database schema supports users, sessions, and OAuth accounts tables

### OpenAPI Documentation
- OpenAPI specification available in `better-auth.yaml`
- Includes comprehensive API endpoint documentation
- Supports interactive API testing and validation