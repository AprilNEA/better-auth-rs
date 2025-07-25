# Better Auth - Rust 🔐

一个受 [Better-Auth](https://www.better-auth.com/) 启发的 Rust 认证框架，提供插件化架构和类型安全的认证解决方案。

## ✨ 特性

- 🔌 **插件化架构** - 轻松扩展和自定义认证流程
- 🛡️ **类型安全** - 利用 Rust 的类型系统确保代码安全
- ⚡ **异步支持** - 全面支持异步操作
- 🗄️ **数据库无关** - 通过适配器模式支持多种数据库
- 🌐 **Web 框架集成** - 支持 Axum（可扩展其他框架）
- 🔑 **多种认证方式** - 邮箱密码、OAuth、双因子认证等

## 🚀 快速开始

### 基础使用

```rust
use better_auth::{BetterAuth, AuthConfig};
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::adapters::MemoryDatabaseAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建配置
    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:3000")
        .password_min_length(8);
    
    // 创建认证系统
    let auth = BetterAuth::new(config)
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .build()
        .await?;
    
    println!("🔐 认证系统已就绪！");
    println!("注册的插件: {:?}", auth.plugin_names());
    
    Ok(())
}
```

### 与 Axum 集成

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
    
    // 创建 Axum 路由器
    let app = auth.axum_router();
    
    // 启动服务器
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

## 🏗️ 架构设计

### 核心组件

- **BetterAuth** - 主要的认证实例
- **AuthPlugin** - 插件系统抽象
- **DatabaseAdapter** - 数据库适配器抽象
- **AuthConfig** - 配置管理

### 插件系统

- **EmailPasswordPlugin** - 邮箱密码认证 ✅
- **OAuthPlugin** - OAuth 认证 🚧
- **TwoFactorPlugin** - 双因子认证 🚧

### 数据库适配器

- **MemoryDatabaseAdapter** - 内存数据库（开发/测试）✅
- **SqlxAdapter** - PostgreSQL 完整支持 ✅
  - 连接池优化
  - 自动迁移脚本
  - 类型安全映射
  - 性能优化索引

## 📁 项目结构

```
better-auth/
├── src/
│   ├── core/           # 核心功能
│   │   ├── auth.rs     # 主要认证逻辑
│   │   ├── config.rs   # 配置管理
│   │   ├── plugin.rs   # 插件抽象
│   │   └── session.rs  # 会话管理
│   ├── plugins/        # 认证插件
│   │   ├── email_password.rs
│   │   ├── oauth.rs
│   │   └── two_factor.rs
│   ├── adapters/       # 数据库和缓存适配器
│   │   ├── database.rs
│   │   └── cache.rs
│   ├── handlers/       # Web 框架集成
│   │   └── axum.rs
│   ├── error.rs        # 错误类型
│   └── types.rs        # 核心类型定义
└── examples/
    └── basic_usage.rs  # 使用示例
```

## 🔧 可用功能

### 认证端点

- `POST /sign-up` - 用户注册
- `POST /sign-in` - 用户登录
- `GET /health` - 健康检查

### 特性标志

```toml
[features]
default = []
axum = ["dep:axum", "dep:tower", "dep:tower-http"]
sqlx-postgres = ["dep:sqlx"]
redis-cache = ["dep:redis"]
```

## 🧪 运行示例

```bash
# 运行基础示例（内存数据库）
cargo run --example basic_usage

# 运行 PostgreSQL 示例
export DATABASE_URL="postgresql://better_auth:password@localhost:5432/better_auth"
cargo run --example postgres_usage --features sqlx-postgres

# 测试编译
cargo check

# 测试 PostgreSQL 功能
cargo check --features sqlx-postgres
```

## 🛠️ 开发状态

### ✅ 已完成
- [x] 核心架构设计
- [x] 插件系统实现
- [x] 邮箱密码认证
- [x] 内存数据库适配器
- [x] 会话管理
- [x] Axum 集成
- [x] 基础示例

### ✅ 最新完成
- [x] **PostgreSQL 数据库支持** - 完整的 SQLx 适配器，包括连接池优化
- [x] **数据库迁移脚本** - 自动化的表结构创建
- [x] **类型安全映射** - PostgreSQL 与 Rust 类型的完美集成
- [x] **性能优化索引** - 针对常见查询的数据库优化

### 🚧 进行中
- [ ] OAuth 插件实现
- [ ] 双因子认证
- [ ] Redis 缓存支持
- [ ] 更多 Web 框架集成

## 🤝 贡献

欢迎贡献代码！请查看项目结构和现有实现来了解如何添加新功能。

## 📄 许可证

MIT License

---

**Better Auth Rust** - 构建安全、可扩展的认证系统 🚀 