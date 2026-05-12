use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;
use tracing::info;

pub async fn init_db(db_path: &str) -> Result<Pool<Sqlite>, Box<dyn std::error::Error + Send + Sync>> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path))?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    info!("Database connected at: {}", db_path);

    // Initialize Schema
    init_schema(&pool).await?;

    // Seed default admin user
    // We will do this from main.rs where config is available
    // OR we can pass admin credentials to init_db.
    
    Ok(pool)
}

pub async fn seed_admin(pool: &Pool<Sqlite>, username: &str, password: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use bcrypt::{hash, DEFAULT_COST};
    let hashed = hash(password, DEFAULT_COST)?;

    sqlx::query("
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, 'Super Admin')
        ON CONFLICT(username) DO NOTHING
    ")
    .bind(username)
    .bind(hashed)
    .execute(pool).await?;

    info!("Admin user '{}' ensured in database.", username);
    
    // Auto-sync after seed
    let _ = sync_mqtt_users(pool).await;

    Ok(())
}

pub async fn sync_mqtt_users(pool: &Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::fs;

    // Fetch all users
    let _rows: Vec<(String, String)> = sqlx::query_as("SELECT username, password_hash FROM users")
        .fetch_all(pool)
        .await?;

    if let Ok(content) = fs::read_to_string("config/ipas.toml") {
        if let Ok(_doc) = content.parse::<toml::Table>() {
            // Future configuration parsing
        }
    }
    
    Ok(())
}

async fn init_schema(pool: &Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Networks Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ").execute(pool).await?;

    // 2. Users Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            callsign TEXT,
            must_change_password INTEGER DEFAULT 1,
            is_enabled INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(network_id) REFERENCES networks(id)
        )
    ").execute(pool).await?;

    // Attempt to add the new columns for existing databases
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN callsign TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 1").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_enabled INTEGER DEFAULT 1").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN password TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE channels ADD COLUMN owner TEXT").execute(pool).await;

    // 3. Channels Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER,
            name TEXT NOT NULL,
            parent_id INTEGER,
            password TEXT,
            owner TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(network_id) REFERENCES networks(id),
            FOREIGN KEY(parent_id) REFERENCES channels(id)
        )
    ").execute(pool).await?;

    // 4. Nodes Table (Added UNIQUE constraint to callsign for UPSERT)
    sqlx::query("
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            hw_id TEXT UNIQUE,
            callsign TEXT UNIQUE,
            current_channel_id INTEGER,
            status TEXT,
            last_lat REAL,
            last_lon REAL,
            last_alt REAL,
            status_code INTEGER,
            last_telemetry TEXT,
            last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(current_channel_id) REFERENCES channels(id)
        )
    ").execute(pool).await?;

    let _ = sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_callsign ON nodes(callsign)").execute(pool).await;

    // 5. Location Logs Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS location_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_callsign TEXT,
            lat REAL,
            lon REAL,
            alt REAL,
            speed REAL,
            status_code INTEGER,
            telemetry_snapshot TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ").execute(pool).await?;

    // 6. Status Definitions Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS status_definitions (
            code INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            color TEXT,
            icon_type TEXT
        )
    ").execute(pool).await?;

    // 7. API Keys Table (for External Apps)
    sqlx::query("
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            key_hash TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ").execute(pool).await?;

    // 8. Seed Root Channel (ID 0)
    let _ = sqlx::query("INSERT INTO channels (id, name, parent_id) VALUES (0, 'Root (Lobby)', NULL) ON CONFLICT(id) DO NOTHING")
        .execute(pool).await;

    // 8.5 Channel Invitations Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS channel_invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            invited_by TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(channel_id) REFERENCES channels(id),
            UNIQUE(channel_id, username)
        )
    ").execute(pool).await?;

    // 9. MQTT Dedicated Devices Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS mqtt_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ").execute(pool).await?;

    // 10. MQTT Subscriptions Table
    sqlx::query("
        CREATE TABLE IF NOT EXISTS mqtt_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            topic TEXT NOT NULL,
            qos INTEGER DEFAULT 0,
            last_payload TEXT,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username, topic)
        )
    ").execute(pool).await?;

    // Attempt to add columns if table already exists (migration)
    let _ = sqlx::query("ALTER TABLE mqtt_subscriptions ADD COLUMN qos INTEGER DEFAULT 0").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE mqtt_subscriptions ADD COLUMN last_payload TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE mqtt_subscriptions ADD COLUMN last_updated DATETIME DEFAULT CURRENT_TIMESTAMP").execute(pool).await;

    // 11. MQTT Topics Monitor Table (for real-time topic monitoring)
    sqlx::query("
        CREATE TABLE IF NOT EXISTS mqtt_topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL UNIQUE,
            last_payload TEXT,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ").execute(pool).await?;

    // Attempt to add columns if table already exists (migration)
    let _ = sqlx::query("ALTER TABLE mqtt_topics ADD COLUMN last_payload TEXT").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE mqtt_topics ADD COLUMN last_updated DATETIME DEFAULT CURRENT_TIMESTAMP").execute(pool).await;

    info!("Database schema initialized successfully.");
    Ok(())
}
