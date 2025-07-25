//! # Better Auth - Rust
//! 
//! A comprehensive authentication framework for Rust, inspired by Better-Auth.
//! 
//! ## Quick Start
//! 
//! ```rust,no_run
//! use better_auth::{BetterAuth, AuthConfig};
//! use better_auth::plugins::EmailPasswordPlugin;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = AuthConfig::new("your-secret-key");
//!     
//!     let auth = BetterAuth::new(config)
//!         .plugin(EmailPasswordPlugin::new())
//!         .build()
//!         .await?;
//!         
//!     Ok(())
//! }
//! ```

pub mod core;
pub mod plugins;
pub mod adapters;
pub mod handlers;
pub mod error;
pub mod types;

// Re-export commonly used items
pub use core::{BetterAuth, AuthBuilder, AuthConfig};
pub use error::{AuthError, AuthResult};
pub use types::{User, Session, Account, AuthRequest, AuthResponse};

#[cfg(feature = "axum")]
pub use handlers::axum::AxumIntegration; 