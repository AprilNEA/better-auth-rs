use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;



/// Core user type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub active: bool,
}

/// Account linking (for OAuth providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_account_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// HTTP method enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Head,
}

/// Authentication request wrapper
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub query: HashMap<String, String>,
}

/// Authentication response wrapper
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// User creation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub password: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// User update data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUser {
    pub email: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: Option<bool>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Session creation data
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Account creation data
#[derive(Debug, Clone)]
pub struct CreateAccount {
    pub user_id: String,
    pub provider: String,
    pub provider_account_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
}

impl CreateUser {
    pub fn new() -> Self {
        Self {
            id: Some(Uuid::new_v4().to_string()),
            email: None,
            name: None,
            image: None,
            password: None,
            metadata: None,
        }
    }
    
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }
    
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }
}

impl Default for CreateUser {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HashMap::new(),
            body: None,
            query: HashMap::new(),
        }
    }
    
    pub fn method(&self) -> &HttpMethod {
        &self.method
    }
    
    pub fn path(&self) -> &str {
        &self.path
    }
    
    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }
    
    pub fn body_as_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        if let Some(body) = &self.body {
            serde_json::from_slice(body)
        } else {
            serde_json::from_str("{}")
        }
    }
}

impl AuthResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }
    
    pub fn json<T: Serialize>(status: u16, data: &T) -> Result<Self, serde_json::Error> {
        let body = serde_json::to_vec(data)?;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        
        Ok(Self {
            status,
            headers,
            body,
        })
    }
    
    pub fn text(status: u16, text: impl Into<String>) -> Self {
        let body = text.into().into_bytes();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());
        
        Self {
            status,
            headers,
            body,
        }
    }
    
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}

// Manual FromRow implementations for PostgreSQL
#[cfg(feature = "sqlx-postgres")]
mod postgres_impls {
    use super::*;
    use sqlx::{FromRow, Row};
    use sqlx::postgres::PgRow;
    
    impl FromRow<'_, PgRow> for User {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                email: row.try_get("email")?,
                name: row.try_get("name")?,
                image: row.try_get("image")?,
                email_verified: row.try_get("email_verified")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
                metadata: {
                    let json_value: sqlx::types::Json<HashMap<String, serde_json::Value>> = 
                        row.try_get("metadata")?;
                    json_value.0
                },
            })
        }
    }
    
    impl FromRow<'_, PgRow> for Session {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                user_id: row.try_get("user_id")?,
                token: row.try_get("token")?,
                expires_at: row.try_get("expires_at")?,
                created_at: row.try_get("created_at")?,
                ip_address: row.try_get("ip_address")?,
                user_agent: row.try_get("user_agent")?,
                active: row.try_get("active")?,
            })
        }
    }
    
    impl FromRow<'_, PgRow> for Account {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            Ok(Self {
                id: row.try_get("id")?,
                user_id: row.try_get("user_id")?,
                provider: row.try_get("provider")?,
                provider_account_id: row.try_get("provider_account_id")?,
                access_token: row.try_get("access_token")?,
                refresh_token: row.try_get("refresh_token")?,
                expires_at: row.try_get("expires_at")?,
                token_type: row.try_get("token_type")?,
                scope: row.try_get("scope")?,
                created_at: row.try_get("created_at")?,
            })
        }
    }
} 