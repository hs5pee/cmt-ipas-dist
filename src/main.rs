//! # CMT-IPAS: Internet Protocol Audio Server
//!
//! Industrial-grade voice communication server with proprietary CMT protocol.
//! Designed for PA systems, RoIP gateways, and consumer IP radios.
//!
//! ## Features
//! - CMT-IPAS protocol (TCP control + UDP voice)
//! - Native Control Bus for device management
//! - Multi-tenant architecture with 3-tier RBAC
//! - Dynamic channel bridging for emergency operations
//! - Opus codec for low-latency, high-quality audio
//!
//! ## Architecture
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              CMT-IPAS Server                │
//! │                                             │
//! │  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
//! │  │ TCP/TLS  │  │   UDP    │  │  Control  │ │
//! │  │ Control  │  │  Voice   │  │  Bridge   │ │
//! │  │ Plane    │  │  Plane   │  │  Module   │ │
//! │  └────┬─────┘  └────┬─────┘  └─────┬─────┘ │
//! │       │              │              │       │
//! │  ┌────┴──────────────┴──────────────┴─────┐ │
//! │  │         Core Engine (Rust)              │ │
//! │  │  - Channel Manager                     │ │
//! │  │  - Auth (Stateless / JWT from Web)      │ │
//! │  │  - Audio Router + Priority System       │ │
//! │  │  - Dynamic Channel Bridging             │ │
//! │  └────────────────────────────────────────┘ │
//! │                    │                        │
//! │              ┌─────┴─────┐                  │
//! │              │ REST API  │                  │
//! │              │ (Web ↔ Engine)               │
//! │              └───────────┘                  │
//! └─────────────────────────────────────────────┘
//! ```

pub mod mumble {
    include!(concat!(env!("OUT_DIR"), "/mumble_proto.rs"));
}

pub mod api;
pub mod db;

use sqlx::{Pool, Sqlite};

use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig as RustlsServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, trace, warn};

use dashmap::DashMap;
use machineid_rs::{Encryption, HWIDComponent, IdBuilder};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::sync::mpsc;

// GUI & System Tray Imports
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, Icon,
};
use tao::event_loop::{ControlFlow, EventLoopBuilder};

#[derive(Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    tls: TlsConfig,
    #[allow(dead_code)]
    admin: AdminConfig,
    mqtt: MqttConfig,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    port: u16,
    #[allow(dead_code)]
    ws_port: u16,
    #[allow(dead_code)]
    register_code: String,
    welcome_message: String,
}

#[derive(Debug, Deserialize)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
}

#[derive(Debug, Deserialize)]
struct AdminConfig {
    #[allow(dead_code)]
    username: String,
    #[allow(dead_code)]
    password: String,
}

#[derive(Debug, Deserialize)]
struct MqttConfig {
    #[allow(dead_code)]
    host: String,
    port: u16,
    ws_port: u16,
    wss_port: u16,
}

// ── Server State Management ─────────────────────────────────────────
struct Client {
    session_id: u32,
    username: String,
    current_channel: std::sync::atomic::AtomicU32,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

pub struct ChannelInfo {
    pub id: u32,
    pub name: String,
}

pub struct ServerState {
    pub clients: DashMap<u32, Arc<Client>>,
    pub channels: DashMap<u32, String>, // channel_id -> channel_name
    next_session_id: AtomicU32,
    next_channel_id: AtomicU32,
    pub hwid: String,
    pub is_registered: std::sync::atomic::AtomicBool,
    pub max_users: std::sync::atomic::AtomicU32,
    pub request_cache: DashMap<String, u64>, // Cache for request deduplication
    pub response_count: DashMap<String, u32>, // Count responses per request
}

// ── HARDCODED PUBLIC KEY ───────────────────────────────────────────
// This is used to verify signatures. The private key stays with you.
const PUBLIC_KEY_HEX: &str = "cd6d3a8082b28790805cbe4e99ca7bf835425c6b0091bac8729986ca9b88e58b";

impl ServerState {
    fn new() -> Self {
        let mut builder = IdBuilder::new(Encryption::SHA256);
        builder
            .add_component(HWIDComponent::CPUID)
            .add_component(HWIDComponent::SystemID);
        let hwid = builder
            .build("CMT-IPAS-PRO")
            .unwrap_or_else(|_| "UNKNOWN-HWID".to_string());

        // Pre-seed with Root channel
        let channels: DashMap<u32, String> = DashMap::new();
        channels.insert(0, "Root (Lobby)".to_string());

        let mut state = Self {
            clients: DashMap::new(),
            channels,
            next_session_id: AtomicU32::new(1),
            next_channel_id: AtomicU32::new(1),
            hwid,
            is_registered: std::sync::atomic::AtomicBool::new(false),
            max_users: std::sync::atomic::AtomicU32::new(3), // Default Trial Limit
            request_cache: DashMap::new(),
            response_count: DashMap::new(),
        };

        state.load_license();
        state
    }

    /// Public method to reload license from disk (used by API)
    pub fn reload_license(&self) {
        // We need a way to call load_license which takes &mut self
        // But since we are using Atomics, we can change load_license to take &self
        self.load_license_internal();
    }

    fn load_license(&mut self) {
        self.load_license_internal();
    }

    /// Load and verify license.dat using Ed25519 digital signature
    fn load_license_internal(&self) {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let license_path = "license.dat";
        if !std::path::Path::new(license_path).exists() {
            self.is_registered.store(false, Ordering::SeqCst);
            self.max_users.store(3, Ordering::SeqCst);
            return;
        }

        match fs::read(license_path) {
            Ok(content) => {
                // Format: [4 bytes Limit][8 bytes Expiry][HWID String Bytes...][64 bytes Signature]
                if content.len() < 64 + 12 {
                    return;
                }

                let (data, signature_bytes) = content.split_at(content.len() - 64);

                // 1. Decode Public Key
                let pub_key_bytes = hex::decode(PUBLIC_KEY_HEX).unwrap_or_default();
                let Ok(public_key_array) = pub_key_bytes.as_slice().try_into() else {
                    return;
                };
                let Ok(public_key) = VerifyingKey::from_bytes(&public_key_array) else {
                    return;
                };

                // 2. Decode Signature
                let Ok(sig) = Signature::from_slice(signature_bytes) else {
                    return;
                };

                // 3. Verify Signature
                if public_key.verify(data, &sig).is_err() {
                    return;
                }

                // 4. Parse Data
                let limit = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0u8; 4]));
                let hwid_in_license = String::from_utf8_lossy(&data[12..]).to_string();

                // 5. Match HWID
                if hwid_in_license.trim() == self.hwid.trim() {
                    self.is_registered.store(true, Ordering::SeqCst);
                    self.max_users.store(limit, Ordering::SeqCst);
                } else {
                    self.is_registered.store(false, Ordering::SeqCst);
                    self.max_users.store(3, Ordering::SeqCst);
                }
            }
            Err(e) => {
                warn!("Failed to read license.dat: {}", e);
                self.is_registered.store(false, Ordering::SeqCst);
                self.max_users.store(3, Ordering::SeqCst);
            }
        }
    }

    /// Create a new channel and return its ID
    pub fn create_channel(&self, name: String) -> u32 {
        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        self.channels.insert(id, name);
        id
    }

    /// Broadcast a raw Mumble message to users in a specific channel
    /// If target_channel is 0 (Root), it performs "Isolation Mode" where users don't see each other
    fn broadcast_to_channel(
        &self,
        target_channel: u32,
        msg_type: u16,
        payload: &[u8],
        skip_session: Option<u32>,
    ) {
        if target_channel == 0 && msg_type == MSG_USER_STATE {
            return;
        }

        let mut full_msg = Vec::new();
        encode_message(&mut full_msg, msg_type, payload);

        let mut count = 0;
        for entry in self.clients.iter() {
            let client = entry.value();
            let client_chan = client.current_channel.load(Ordering::SeqCst);
            if client_chan == target_channel {
                if Some(client.session_id) != skip_session {
                    let _ = client.tx.send(full_msg.clone());
                    count += 1;
                }
            }
        }

        if msg_type == 1 && count == 0 {
            warn!(
                "Audio packet for channel {} found 0 recipients (sender skipped)",
                target_channel
            );
        }
    }

    /// Global broadcast (e.g. for Server Config or Text messages to all)
    fn broadcast_global(&self, msg_type: u16, payload: &[u8], skip_session: Option<u32>) {
        let mut full_msg = Vec::new();
        encode_message(&mut full_msg, msg_type, payload);

        for entry in self.clients.iter() {
            let client = entry.value();
            if Some(client.session_id) != skip_session {
                let _ = client.tx.send(full_msg.clone());
            }
        }
    }

    /// Public broadcast for use by api.rs (channel creation, user moves)
    pub fn broadcast_global_raw(&self, msg_type: u16, payload: &[u8], skip_session: Option<u32>) {
        self.broadcast_global(msg_type, payload, skip_session);
    }
}

/// Process incoming telemetry/GPS data from MQTT and store in DB
async fn process_telemetry(db: &Pool<Sqlite>, payload: &[u8]) {
    let raw = String::from_utf8_lossy(payload);

    // Expected JSON: {"callsign": "HS5PEE-1", "lat": 18.7, "lng": 98.9, "alt": 300, "status": 0, "msg": "Testing"}
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(json) => {
            let callsign = json["callsign"].as_str().unwrap_or("unknown");
            let lat = json["lat"].as_f64().unwrap_or(0.0);
            let lon = json["lng"].as_f64().unwrap_or(0.0);
            let alt = json["alt"].as_f64().unwrap_or(0.0);
            let status = json["status"].as_i64().unwrap_or(0);
            let msg = json["msg"].as_str().unwrap_or("");

        // Security Check: Does this user/callsign exist in our system?
        let user_exists: (i64,) = match sqlx::query_as("SELECT COUNT(*) FROM users WHERE callsign = ? OR username = ?")
            .bind(callsign)
            .bind(callsign)
            .fetch_one(db)
            .await {
                Ok(res) => res,
                Err(_) => (0,),
            };

        if user_exists.0 == 0 {
            warn!("Rejected telemetry from unknown node/callsign: {}", callsign);
            return;
        }

        // 1. Update nodes table first
        let update_res = sqlx::query("
            UPDATE nodes SET
                last_lat = ?, last_lon = ?, last_alt = ?, status_code = ?, last_telemetry = ?, last_seen_at = CURRENT_TIMESTAMP
            WHERE callsign = ?
        ")
        .bind(lat).bind(lon).bind(alt).bind(status).bind(msg).bind(callsign)
        .execute(db)
        .await;

        let mut inserted = false;
        match update_res {
            Ok(res) if res.rows_affected() == 0 => {
                // Not found, so insert it
                let insert_res = sqlx::query("
                    INSERT INTO nodes (callsign, last_lat, last_lon, last_alt, status_code, last_telemetry)
                    VALUES (?, ?, ?, ?, ?, ?)
                ")
                .bind(callsign).bind(lat).bind(lon).bind(alt).bind(status).bind(msg)
                .execute(db)
                .await;

                if let Err(e) = insert_res {
                    error!("❌ Error inserting telemetry to 'nodes' table: {}", e);
                } else {
                    inserted = true;
                }
            }
            Ok(_) => { inserted = true; } // Updated successfully
            Err(e) => error!("❌ Error updating telemetry in 'nodes' table: {}", e),
        }

        if !inserted {
            return; // Don't log to location_logs if we couldn't save to nodes
        }
        // 2. Log to location_logs
        let res2 = sqlx::query("
            INSERT INTO location_logs (node_callsign, lat, lon, alt, status_code, telemetry_snapshot)
            VALUES (?, ?, ?, ?, ?, ?)
        ")
        .bind(callsign)
        .bind(lat)
        .bind(lon)
        .bind(alt)
        .bind(status)
        .bind(msg)
        .execute(db)
        .await;

        info!("📍 GPS Updated: {} at ({}, {})", callsign, lat, lon);
        }
        Err(e) => {
            error!("❌ Invalid JSON telemetry received: {}", e);
        }
    }
}

/// Process subscription report from MQTT device
/// Expected JSON: {"username": "device_name", "subscriptions": [{"topic": "cmt/nodes/telemetry", "qos": 0}]}
async fn process_subscription_report(db: &Pool<Sqlite>, payload: &[u8]) {
    let raw = String::from_utf8_lossy(payload);

    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(json) => {
            let username = json["username"].as_str().unwrap_or("unknown");

            // Security Check: Does this device exist in mqtt_devices?
            let device_exists: (i64,) = match sqlx::query_as("SELECT COUNT(*) FROM mqtt_devices WHERE username = ?")
                .bind(username)
                .fetch_one(db)
                .await {
                    Ok(res) => res,
                    Err(_) => (0,),
                };

            if device_exists.0 == 0 {
                warn!("Rejected subscription report from unknown device: {}", username);
                return;
            }

            // Process subscriptions list
            if let Some(subs) = json["subscriptions"].as_array() {
                for sub in subs {
                    if let Some(topic) = sub["topic"].as_str() {
                        let qos = sub["qos"].as_i64().unwrap_or(0);

                        // Handle payload: can be string or any JSON type
                        let payload_sample = if sub["payload"].is_null() {
                            None
                        } else {
                            // Serialize any JSON value to string
                            serde_json::to_string(&sub["payload"]).ok()
                        };

                        // Insert or update subscription
                        match sqlx::query("
                            INSERT INTO mqtt_subscriptions (username, topic, qos, last_payload)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(username, topic) DO UPDATE SET
                                qos = excluded.qos,
                                last_payload = excluded.last_payload,
                                last_updated = CURRENT_TIMESTAMP
                        ")
                        .bind(username)
                        .bind(topic)
                        .bind(qos)
                        .bind(&payload_sample)
                        .execute(db)
                        .await
                        {
                            Ok(_) => {
                                info!("✅ Subscription updated: {} -> {}", username, topic);
                            }
                            Err(e) => {
                                error!("❌ Failed to save subscription: {} -> {}: {}", username, topic, e);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            error!("❌ Invalid JSON subscription report received: {}", e);
        }
    }
}

/// Process channel list request via MQTT
/// Send JSON response with available channels for the user
async fn process_channel_list_request(
    db: &Pool<Sqlite>,
    server_state: &Arc<ServerState>,
    mqtt_client: &Arc<tokio::sync::Mutex<rumqttc::AsyncClient>>,
    username: &str,
) {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Check if username exists in Active Sessions and get current channel
    let mut found_in_sessions = false;
    let mut current_channel_id = 0;
    for entry in server_state.clients.iter() {
        if entry.value().username == username {
            found_in_sessions = true;
            current_channel_id = entry.value().current_channel.load(Ordering::SeqCst);
            info!("✅ [DEBUG] Username '{}' found in Active Sessions (session_id: {}, channel_id: {})", username, entry.key(), current_channel_id);
            break;
        }
    }

    if !found_in_sessions {
        info!("❌ [DEBUG] Username '{}' NOT found in Active Sessions. Skipping response.", username);
        // List all active session usernames for debugging
        let active_usernames: Vec<String> = server_state.clients.iter()
            .map(|entry| entry.value().username.clone())
            .collect();
        info!("🔍 [DEBUG] Active session usernames: {:?}", active_usernames);
        return; // ONLY send if user is active
    }

    // Get current channel name
    let current_channel_name = server_state.channels.get(&current_channel_id)
        .map(|entry| entry.value().clone())
        .unwrap_or_else(|| "Unknown".to_string());

    // Simple debounce: check if request was made within last 1 second
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let cache_key = format!("channel_list_request_{}", username);
    let last_request = server_state.request_cache.get(&cache_key);

    if let Some(last_time) = last_request {
        if now - *last_time < 1 {
            info!("⏭️  Skipping duplicate channel list request for {} (debounce)", username);
            return;
        }
    }

    // Update cache
    server_state.request_cache.insert(cache_key, now);

    // Get all channels
    let channels: Vec<(i64, String, Option<String>)> = match sqlx::query_as("SELECT id, name, password FROM channels WHERE id != 0")
        .fetch_all(db)
        .await {
            Ok(ch) => {
                info!("📊 Fetched {} channels from database", ch.len());
                ch
            },
            Err(e) => {
                error!("Failed to fetch channels: {}", e);
                return;
            }
        };

    // Get user's invited channels
    let invited_channels: Vec<i64> = match sqlx::query_scalar("SELECT channel_id FROM channel_invitations WHERE username = ?")
        .bind(&username)
        .fetch_all(db)
        .await {
            Ok(ic) => {
                info!("📊 User {} has {} invitations", username, ic.len());
                ic
            },
            Err(e) => {
                error!("Failed to fetch invited channels: {}", e);
                return;
            }
        };

    // Build channel list with access info (only include accessible channels)
    let mut channel_list = Vec::new();
    for (id, name, password) in channels {
        let is_private = password.is_some();
        let has_invitation = invited_channels.contains(&id);
        let can_access = !is_private || has_invitation;

        if can_access {
            channel_list.push(serde_json::json!({
                "id": id,
                "name": name,
                "is_private": is_private,
                "has_invitation": has_invitation,
                "can_access": can_access
            }));
        }
    }

    let response = serde_json::json!({
        "username": username,
        "current_channel": {
            "id": current_channel_id,
            "name": current_channel_name
        },
        "channels": channel_list
    });

    // Send response via MQTT to cmt/user/channel/list/{username}
    let client = mqtt_client.lock().await;
    let topic = format!("cmt/user/channel/list/{}", username);
    info!("🔍 [DEBUG] Publishing to topic: '{}' with username: '{}'", topic, username);
    let payload = serde_json::to_vec(&response).unwrap_or_default();
    match client.publish(topic, rumqttc::QoS::AtMostOnce, false, payload).await {
        Ok(_) => info!("✅ Sent channel list to {}", username),
        Err(e) => error!("❌ Failed to send channel list: {}", e),
    }
}

/// Process channel move request via MQTT
/// Move user to requested channel
async fn process_channel_move_request(
    db: &Pool<Sqlite>,
    server_state: &Arc<ServerState>,
    payload: &[u8],
) {
    // Parse request
    let request: serde_json::Value = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to parse move request: {}", e);
            return;
        }
    };

    let username = request.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let session_id = request.get("session_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let channel_id = request.get("channel_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if username.is_empty() || session_id == 0 || channel_id == 0 {
        error!("Invalid move request: username={}, session_id={}, channel_id={}", username, session_id, channel_id);
        return;
    }

    // Find client and move
    let mut moved = false;
    for entry in server_state.clients.iter() {
        let client = entry.value();
        if client.username == username && *entry.key() == session_id {
            let old_chan = client.current_channel.load(std::sync::atomic::Ordering::SeqCst);
            client.current_channel.store(channel_id, std::sync::atomic::Ordering::SeqCst);

            // Send UserState update to ALL clients
            let user_state_msg = crate::mumble::UserState {
                session: Some(session_id),
                channel_id: Some(channel_id),
                ..Default::default()
            };
            server_state.broadcast_global_raw(
                crate::MSG_USER_STATE,
                &user_state_msg.encode_to_vec(),
                None,
            );

            info!("✅ Moved user {} from channel {} to {} via MQTT", username, old_chan, channel_id);
            moved = true;
            break;
        }
    }

    if !moved {
        error!("❌ Failed to move user {} (session {}): client not found", username, session_id);
    }
}

/// Process secure channel move request for a specific user via MQTT
/// Verify access before moving
async fn process_user_move_request(
    db: &Pool<Sqlite>,
    server_state: &Arc<ServerState>,
    mqtt_client: &Arc<tokio::sync::Mutex<rumqttc::AsyncClient>>,
    username: &str,
    payload: &[u8],
) {
    // Parse request
    let channel_id = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(payload) {
        json.get("channel_id")
            .and_then(|v| v.as_u64().map(|id| id as u32))
            .or_else(|| json.as_u64().map(|id| id as u32))
            .unwrap_or(0)
    } else {
        String::from_utf8_lossy(payload).trim().parse::<u32>().unwrap_or(0)
    };

    if username.is_empty() || channel_id == 0 {
        error!("Invalid user move request: username={}, channel_id={}", username, channel_id);
        return;
    }

    // 1. Check access
    let channel_info: Option<(Option<String>,)> = match sqlx::query_as("SELECT password FROM channels WHERE id = ?")
        .bind(channel_id as i64)
        .fetch_optional(db)
        .await {
            Ok(ci) => ci,
            Err(e) => {
                error!("Failed to check channel access: {}", e);
                return;
            }
        };

    if let Some((password,)) = channel_info {
        if password.is_some() {
            let invited: (i64,) = match sqlx::query_as("SELECT COUNT(*) FROM channel_invitations WHERE channel_id = ? AND username = ?")
                .bind(channel_id as i64)
                .bind(username)
                .fetch_one(db)
                .await {
                    Ok(res) => res,
                    Err(_) => (0,),
                };
            if invited.0 == 0 {
                warn!("❌ Access denied for user {} to private channel {}", username, channel_id);
                return;
            }
        }
    } else {
        error!("❌ Channel {} not found", channel_id);
        return;
    }

    // 2. Move sessions
    let mut moved = false;
    for entry in server_state.clients.iter() {
        let client = entry.value();
        if client.username == username {
            let old_chan = client.current_channel.load(std::sync::atomic::Ordering::SeqCst);
            client.current_channel.store(channel_id, std::sync::atomic::Ordering::SeqCst);

            let user_state_msg = crate::mumble::UserState {
                session: Some(client.session_id),
                channel_id: Some(channel_id),
                ..Default::default()
            };
            server_state.broadcast_global_raw(crate::MSG_USER_STATE, &user_state_msg.encode_to_vec(), None);

            info!("✅ Moved user {} from channel {} to {} via MQTT secure request", username, old_chan, channel_id);
            moved = true;
        }
    }

    if moved {
        // Auto-refresh channel list
        process_channel_list_request(db, server_state, mqtt_client, username).await;
    } else {
        warn!("❌ No active session for user {}", username);
    }
}

/// Process wildcard message from cmt/# for auto-discovery
/// Extract username from topic and auto-create/update subscription
/// Also record topic in mqtt_topics for monitoring
async fn process_wildcard_message(
    db: &Pool<Sqlite>,
    server_state: &Arc<ServerState>,
    mqtt_client: &Arc<tokio::sync::Mutex<rumqttc::AsyncClient>>,
    topic: &str,
    payload: &[u8],
) {
    // Special handling for telemetry topic
    if topic == "cmt/nodes/telemetry" {
        process_telemetry(db, payload).await;
    }

    // Special handling for channel list request
    if topic.starts_with("cmt/channels/list/") {
        // Try to get username from payload (JSON or Plain String)
        let username = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(payload) {
            // If it's valid JSON, try to get "username" field, or use the JSON string itself
            json.get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    json.as_str().map(|s| s.to_string())
                        .unwrap_or_else(|| topic.strip_prefix("cmt/channels/list/").unwrap_or("").to_string())
                })
        } else {
            // If not JSON, try plain string from payload
            let s = String::from_utf8_lossy(payload).trim().to_string();
            if !s.is_empty() {
                s
            } else {
                // Fallback to topic extraction
                topic.strip_prefix("cmt/channels/list/").unwrap_or("").to_string()
            }
        };

        if username.is_empty() {
            warn!("⚠️ Received channel list request with empty username from topic: {}", topic);
            return;
        }

        info!("🔍 [DEBUG] Received channel list request for username: '{}' from topic: {}", username, topic);
        process_channel_list_request(db, server_state, mqtt_client, &username).await;
        return;
    }

    // Special handling for channel move request
    if topic == "cmt/channels/move" {
        process_channel_move_request(db, server_state, payload).await;
        return;
    }

    // Special handling for secure user channel move request
    if topic.starts_with("cmt/user/channel/move/") {
        let username = topic.strip_prefix("cmt/user/channel/move/").unwrap_or("");
        process_user_move_request(db, server_state, mqtt_client, username, payload).await;
        return;
    }

    // Parse payload as JSON for display
    let payload_str = match String::from_utf8_lossy(payload).parse::<serde_json::Value>() {
        Ok(json) => Some(serde_json::to_string(&json).unwrap_or_else(|_| "{}".to_string())),
        Err(_) => Some(String::from_utf8_lossy(payload).to_string()),
    };

    // Record topic in mqtt_topics for monitoring
    match sqlx::query("
        INSERT INTO mqtt_topics (topic, last_payload)
        VALUES (?, ?)
        ON CONFLICT(topic) DO UPDATE SET
            last_payload = excluded.last_payload,
            last_updated = CURRENT_TIMESTAMP
    ")
    .bind(topic)
    .bind(&payload_str)
    .execute(db)
    .await
    {
        Ok(_) => {
            info!("✅ Topic recorded: {}", topic);
        }
        Err(e) => {
            error!("❌ Failed to record topic: {}: {}", topic, e);
        }
    }

    // Extract username from topic pattern: cmt/nodes/{username}/...
    let username = match topic.split('/').nth(2) {
        Some(u) if !u.is_empty() => u,
        _ => {
            // Try other patterns
            // cmt/{username}/...
            match topic.split('/').nth(1) {
                Some(u) if !u.is_empty() => u,
                _ => return,
            }
        }
    };

    // Security Check: Does this device exist in mqtt_devices?
    let device_exists: (i64,) = match sqlx::query_as("SELECT COUNT(*) FROM mqtt_devices WHERE username = ?")
        .bind(username)
        .fetch_one(db)
        .await {
            Ok(res) => res,
            Err(_) => (0,),
        };

    if device_exists.0 == 0 {
        // Unknown device, skip subscription creation
        return;
    }

    // Auto-create/update subscription
    match sqlx::query("
        INSERT INTO mqtt_subscriptions (username, topic, qos, last_payload)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(username, topic) DO UPDATE SET
            last_payload = excluded.last_payload,
            last_updated = CURRENT_TIMESTAMP
    ")
    .bind(username)
    .bind(topic)
    .bind(0) // Default QoS for auto-discovered subscriptions
    .bind(&payload_str)
    .execute(db)
    .await
    {
        Ok(_) => {
            info!("✅ Auto-discovered subscription: {} -> {}", username, topic);
        }
        Err(e) => {
            error!("❌ Failed to save auto-discovered subscription: {} -> {}: {}", username, topic, e);
        }
    }
}

/// CMT-IPAS: Internet Protocol Audio Server
#[derive(Parser, Debug)]
#[command(name = "cmt-ipas")]
#[command(version, about = "CMT-IPAS: Internet Protocol Audio Server", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/ipas.toml")]
    config: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn load_icon(path: &std::path::Path) -> Icon {
    let (icon_rgba, icon_width, icon_height) = {
        let image = image::open(path)
            .expect("Failed to open icon path")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };
    Icon::from_rgba(icon_rgba, icon_width, icon_height).expect("Failed to create icon")
}

async fn run_server(
    _args: Args,
    config: Config,
    state: Arc<ServerState>,
    db_pool: Pool<Sqlite>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    // ── Load Channels from DB ───────────────────────────────────────
    let db_channels: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM channels")
        .fetch_all(&db_pool)
        .await
        .unwrap_or_default();

    let mut max_ch_id = 0;
    for (id, name) in db_channels {
        let ch_id = id as u32;
        state.channels.insert(ch_id, name);
        if ch_id > max_ch_id {
            max_ch_id = ch_id;
        }
    }
    if max_ch_id > 0 {
        state
            .next_channel_id
            .store(max_ch_id + 1, std::sync::atomic::Ordering::SeqCst);
        info!("Loaded {} channels from database", state.channels.len() - 1); // -1 for Root
    }

    // ── TLS / Certificate Setup ─────────────────────────────────────
    let (cert_chain, private_key) = if fs::metadata(&config.tls.cert_path).is_ok()
        && fs::metadata(&config.tls.key_path).is_ok()
    {
        info!(
            "Loading TLS certificates from files: {}, {}",
            config.tls.cert_path, config.tls.key_path
        );
        let cert_file = fs::File::open(&config.tls.cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

        let key_file = fs::File::open(&config.tls.key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let private_key = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| "No private key found in key file")?;

        (cert_chain, private_key)
    } else {
        warn!("TLS certificates not found. Generating self-signed certificate...");
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])?;
        fs::write(&config.tls.cert_path, cert.cert.pem())?;
        fs::write(&config.tls.key_path, cert.key_pair.serialize_pem())?;
        info!(
            "Saved self-signed certs to {}, {}",
            config.tls.cert_path, config.tls.key_path
        );

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(
            cert.cert.der().to_vec(),
        )];
        let private_key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
        (cert_chain, private_key)
    };

    let server_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // ── Internal MQTT Broker (rumqttd) ─────────────────────────────
    let rumqttd_config_str = format!(
        "\
id = 0\n\
[router]\n\
dir = \"config/rumqttd\"\n\
max_connections = 10000\n\
max_segment_size = 1048576\n\
max_segment_count = 10\n\
max_outgoing_packet_count = 200\n\
\n\
[console]\n\
listen = \"0.0.0.0:3030\"\n\
\n\
[v4.1]\n\
name = \"tcp-internal\"\n\
listen = \"0.0.0.0:{}\"\n\
next_connection_delay_ms = 1\n\
[v4.1.connections]\n\
connection_timeout_ms = 10000\n\
max_client_id_len = 256\n\
throttle_delay_ms = 0\n\
max_payload_size = 5120\n\
max_inflight_count = 100\n\
max_inflight_size = 1024\n\
\n\
[ws.1]\n\
name = \"ws-dashboard\"\n\
listen = \"0.0.0.0:{}\"\n\
next_connection_delay_ms = 1\n\
[ws.1.connections]\n\
connection_timeout_ms = 10000\n\
max_client_id_len = 256\n\
throttle_delay_ms = 0\n\
max_payload_size = 5120\n\
max_inflight_count = 100\n\
max_inflight_size = 1024\n\
",
        config.mqtt.port,
        config.mqtt.ws_port
    );

    let _ = fs::create_dir_all("config/rumqttd");

    // Parse rumqttd config - if it fails (e.g. WSS TLS format issue),
    // fall back to TCP+WS only to keep the server running
    match toml::from_str::<rumqttd::Config>(&rumqttd_config_str) {
        Ok(mut r_cfg) => {
            // Apply Database Auth Handler to TCP Server
            if let Some(v4) = r_cfg.v4.as_mut() {
                if let Some(server) = v4.get_mut("1") {
                    let auth_pool = db_pool.clone();
                    server.set_auth_handler(move |_client_id, username, password| {
                        let pool = auth_pool.clone();
                        async move {
                            if username == "__internal_system_node__" && password == "super_secret_internal_key_2024" { return true; }
                            if let Ok((hash, enabled)) = sqlx::query_as::<_, (String, i64)>("SELECT password_hash, is_enabled FROM users WHERE username = ? UNION ALL SELECT password_hash, is_enabled FROM mqtt_devices WHERE username = ? LIMIT 1")
                                .bind(&username)
                                .bind(&username)
                                .fetch_one(&pool)
                                .await
                            {
                                if enabled == 0 { return false; }
                                tokio::task::spawn_blocking(move || {
                                    bcrypt::verify(&password, &hash).unwrap_or(false)
                                }).await.unwrap_or(false)
                            } else {
                                false
                            }
                        }
                    });
                }
            }
            // Apply Database Auth Handler to WS Server
            if let Some(ws) = r_cfg.ws.as_mut() {
                if let Some(server) = ws.get_mut("1") {
                    let auth_pool = db_pool.clone();
                    server.set_auth_handler(move |_client_id, username, password| {
                        let pool = auth_pool.clone();
                        async move {
                            if let Ok((hash, enabled)) = sqlx::query_as::<_, (String, i64)>("
                                SELECT password_hash, is_enabled FROM users WHERE username = ?
                                UNION ALL
                                SELECT password_hash, is_enabled FROM mqtt_devices WHERE username = ?
                                LIMIT 1
                            ")
                                .bind(&username)
                                .bind(&username)
                                .fetch_one(&pool)
                                .await
                            {
                                if enabled == 0 { return false; }
                                tokio::task::spawn_blocking(move || {
                                    bcrypt::verify(&password, &hash).unwrap_or(false)
                                }).await.unwrap_or(false)
                            } else {
                                false
                            }
                        }
                    });
                }
            }

            std::thread::spawn(move || {
                let mut broker = rumqttd::Broker::new(r_cfg);
                if let Err(e) = broker.start() {
                    warn!("Control Bus stopped: {}", e);
                }
            });
            info!(
                "Control Bus starting on TCP:{}, WS:{} (WSS handled by proxy) - Secure Auth Enabled",
                config.mqtt.port, config.mqtt.ws_port
            );
        }
        Err(e) => {
            warn!("WS config error: {}. Retrying...", e);
            // Fallback: TCP + WS only
            let fallback_cfg_str = format!(
                "id = 0\n[router]\ndir = \"config/rumqttd\"\nmax_connections = 10000\nmax_segment_size = 1048576\nmax_segment_count = 10\nmax_outgoing_packet_count = 200\n\n[console]\nlisten = \"0.0.0.0:3030\"\n\n[v4.1]\nname = \"v4-1\"\nlisten = \"0.0.0.0:{}\"\nnext_connection_delay_ms = 1\n[v4.1.connections]\nconnection_timeout_ms = 10000\nmax_client_id_len = 256\nthrottle_delay_ms = 0\nmax_payload_size = 5120\nmax_inflight_count = 100\nmax_inflight_size = 1024\n\n[ws.1]\nname = \"ws-1\"\nlisten = \"0.0.0.0:{}\"\nnext_connection_delay_ms = 1\n[ws.1.connections]\nconnection_timeout_ms = 10000\nmax_client_id_len = 256\nthrottle_delay_ms = 0\nmax_payload_size = 5120\nmax_inflight_count = 100\nmax_inflight_size = 1024\n",
                config.mqtt.port, config.mqtt.ws_port
            );
            if let Ok(mut r_cfg) = toml::from_str::<rumqttd::Config>(&fallback_cfg_str) {
                // Apply Database Auth Handler to TCP Server (Fallback)
                if let Some(v4) = r_cfg.v4.as_mut() {
                    if let Some(server) = v4.get_mut("v4-1") {
                        let auth_pool = db_pool.clone();
                        server.set_auth_handler(move |_client_id, username, password| {
                            let pool = auth_pool.clone();
                            async move {
                                // Hardcoded bypass for internal system node
                                if username == "__internal_system_node__" && password == "super_secret_internal_key_2024" {
                                    return true;
                                }

                                if let Ok((hash, enabled)) = sqlx::query_as::<_, (String, i64)>("
                                    SELECT password_hash, is_enabled FROM users WHERE username = ?
                                    UNION ALL
                                    SELECT password_hash, is_enabled FROM mqtt_devices WHERE username = ?
                                    LIMIT 1
                                ")
                                    .bind(&username)
                                    .bind(&username)
                                    .fetch_one(&pool)
                                    .await
                                {
                                    if enabled == 0 { return false; }
                                    tokio::task::spawn_blocking(move || {
                                        bcrypt::verify(&password, &hash).unwrap_or(false)
                                    }).await.unwrap_or(false)
                                } else {
                                    false
                                }
                            }
                        });
                    }
                }
                std::thread::spawn(move || {
                    let mut broker = rumqttd::Broker::new(r_cfg);
                    if let Err(e) = broker.start() {
                        warn!("Control Bus (fallback) stopped: {}", e);
                    }
                });
                warn!("Control Bus running in fallback mode (TCP+WS only, no WSS)");
            }
        }
    }

    // ── WSS Proxy (Bypassing rumqttd 0.18 rigid mTLS requirement) ──
    let wss_acceptor = acceptor.clone();
    let ws_port = config.mqtt.ws_port;
    let wss_port = config.mqtt.wss_port;
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{}", wss_port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                info!("Control Bus Proxy on WSS:{}", wss_port);
                loop {
                    if let Ok((stream, _peer_addr)) = listener.accept().await {
                        let tls_acceptor = wss_acceptor.clone();
                        tokio::spawn(async move {
                            if let Ok(mut tls_stream) = tls_acceptor.accept(stream).await {
                                if let Ok(mut plain_stream) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ws_port)).await {
                                    let (mut ri, mut wi) = tokio::io::split(tls_stream);
                                    let (mut ro, mut wo) = tokio::io::split(plain_stream);
                                    let _ = tokio::join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi)
                                    );
                                }
                            }
                        });
                    }
                }
            }
            Err(e) => {
                error!("Failed to start WSS Proxy on port {}: {}", wss_port, e);
            }
        }
    });

    std::thread::sleep(std::time::Duration::from_millis(500));

    // ── MQTT Client to listen for GPS/Telemetry and Subscriptions ─────────
    // Note: rumqttc client library doesn't support WebSocket transport directly.
    // We use TCP connection to read subscriptions from the broker.
    // WS and WSS ports are handled by the broker itself, but we can only connect via TCP.
    let db_for_mqtt = db_pool.clone();
    let server_state_for_mqtt = state.clone();
    let mqtt_port = config.mqtt.port;

    tokio::spawn(async move {
        loop {
            info!("📡 Control Bus: Attempting to connect to internal loopback...");
            let mut mqttoptions = rumqttc::MqttOptions::new("ipas-internal-subscriber", "127.0.0.1", mqtt_port);
            mqttoptions.set_keep_alive(std::time::Duration::from_secs(5));
            mqttoptions.set_credentials("__internal_system_node__", "super_secret_internal_key_2024");

            let (mqtt_client, mut mqtt_eventloop) = rumqttc::AsyncClient::new(mqttoptions, 10);
            let mqtt_client_for_publish = Arc::new(tokio::sync::Mutex::new(mqtt_client.clone()));

            // Try to subscribe to multiple topics
            match mqtt_client.subscribe("cmt/internal/subscriptions", rumqttc::QoS::AtMostOnce).await {
                Ok(_) => info!("✅ Control Bus: Linked to subscriptions stream"),
                Err(e) => {
                    error!("❌ Control Bus: Failed to link subscriptions: {}. Retrying in 5s...", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }

            // Subscribe to cmt/# for auto-discovery
            match mqtt_client.subscribe("cmt/#", rumqttc::QoS::AtMostOnce).await {
                Ok(_) => info!("✅ Control Bus: Linked to wildcard stream cmt/#"),
                Err(e) => {
                    error!("❌ Control Bus: Failed to link wildcard: {}. Retrying in 5s...", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }

            // Main loop for polling
            loop {
                match mqtt_eventloop.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(p))) => {
                        if p.topic == "cmt/internal/subscriptions" {
                            process_subscription_report(&db_for_mqtt, &p.payload).await;
                        } else if p.topic.starts_with("cmt/") && p.topic != "cmt/internal/subscriptions" {
                            // Auto-discovery: process any message under cmt/#
                            // Spawn a separate task to avoid deadlocking the event loop during publish
                            let db_task = db_for_mqtt.clone();
                            let state_task = server_state_for_mqtt.clone();
                            let mqtt_task = mqtt_client_for_publish.clone();
                            let topic_task = p.topic.clone();
                            let payload_task = p.payload.to_vec();
                            tokio::spawn(async move {
                                process_wildcard_message(&db_task, &state_task, &mqtt_task, &topic_task, &payload_task).await;
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        error!("❌ Control Bus: Stream disconnected: {}. Reconnecting...", e);
                        break; // Exit inner loop to reconnect
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

    // ── TCP Listener ───────────────────────────────────────────────
    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    let listener = TcpListener::bind(&addr).await?;

    info!("Control Plane: {}", addr);
    info!(
        "Control Bus on TCP:{}, WS:{}, WSS:{}",
        config.mqtt.port, config.mqtt.ws_port, config.mqtt.wss_port
    );

    // ── Start REST API Server ──────────────────────────────────────
    let db_clone = db_pool.clone();
    let api_port = config.server.ws_port;
    let state_for_api = state.clone();
    tokio::spawn(async move {
        api::start_api_server(db_clone, state_for_api, api_port).await;
    });

    info!("Ready for connections (CMT-IPAS Industrial Protocol)");

    let welcome_msg = Arc::new(config.server.welcome_message.clone());

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let welcome = welcome_msg.clone();
        let state = state.clone();

        tokio::spawn(async move {
            info!("New connection from: {}", peer_addr);

            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    info!("Secure channel established for {}", peer_addr);
                    let result = handle_client(tls_stream, peer_addr, &welcome, state).await;
                    if let Err(e) = result {
                        let err_msg = e.to_string();
                        if !err_msg.contains("close_notify") && !err_msg.contains("unexpected EOF")
                        {
                            warn!("Client {} session ended: {}", peer_addr, err_msg);
                        } else {
                            info!("Client {} disconnected", peer_addr);
                        }
                    }
                }
                Err(e) => {
                    warn!("Secure handshake failed for {}: {}", peer_addr, e);
                }
            }
        });
    }
}

// ── Mumble Protocol Message Types ──────────────────────────────────
const MSG_VERSION: u16 = 0;
const MSG_UDP_TUNNEL: u16 = 1;
const MSG_AUTHENTICATE: u16 = 2;
const MSG_PING: u16 = 3;
const MSG_REJECT: u16 = 4;
const MSG_SERVER_SYNC: u16 = 5;
pub const MSG_CHANNEL_STATE: u16 = 7;
pub const MSG_USER_REMOVE: u16 = 8;
pub const MSG_USER_STATE: u16 = 9;
const MSG_CRYPT_SETUP: u16 = 15;
const MSG_CODEC_VERSION: u16 = 21;
const MSG_SERVER_CONFIG: u16 = 24;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

async fn read_message(
    stream: &mut TlsStream<TcpStream>,
) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let msg_type = stream.read_u16().await?;
    let msg_len = stream.read_u32().await? as u64;

    if msg_len > 1024 * 1024 {
        return Err(format!("Message too large: {} bytes (type {})", msg_len, msg_type).into());
    }

    let mut payload = vec![0u8; msg_len as usize];
    stream.read_exact(&mut payload).await?;
    Ok((msg_type, payload))
}

/// Generic version of read_message that works with any AsyncRead (e.g. ReadHalf)
async fn read_message_generic<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(u16, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncReadExt;
    let msg_type = stream.read_u16().await?;
    let msg_len = stream.read_u32().await? as u64;

    if msg_len > 1024 * 1024 {
        return Err(format!("Message too large: {} bytes (type {})", msg_len, msg_type).into());
    }

    let mut payload = vec![0u8; msg_len as usize];
    stream.read_exact(&mut payload).await?;
    Ok((msg_type, payload))
}

fn decode_mumble_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let v = data[0];
    if (v & 0x80) == 0x00 {
        Some((v as u64, 1))
    } else if (v & 0xC0) == 0x80 {
        if data.len() < 2 {
            return None;
        }
        Some((((v & 0x3F) as u64) << 8 | data[1] as u64, 2))
    } else if (v & 0xE0) == 0xC0 {
        if data.len() < 3 {
            return None;
        }
        Some((
            ((v & 0x1F) as u64) << 16 | (data[1] as u64) << 8 | data[2] as u64,
            3,
        ))
    } else if (v & 0xF0) == 0xE0 {
        if data.len() < 4 {
            return None;
        }
        Some((
            ((v & 0x0F) as u64) << 24
                | (data[1] as u64) << 16
                | (data[2] as u64) << 8
                | data[3] as u64,
            4,
        ))
    } else if (v & 0xF0) == 0xF0 {
        match v & 0x0C {
            0x00 => {
                if data.len() < 5 {
                    return None;
                }
                let val = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                Some((val as u64, 5))
            }
            0x04 => {
                if data.len() < 9 {
                    return None;
                }
                let val = u64::from_be_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]);
                Some((val, 9))
            }
            _ => None,
        }
    } else {
        None
    }
}

async fn read_varint_with_bytes(
    stream: &mut TlsStream<TcpStream>,
) -> Result<(u64, Vec<u8>), std::io::Error> {
    let mut b = [0u8; 1];
    stream.read_exact(&mut b).await?;
    let v = b[0];
    let mut bytes = vec![v];

    if (v & 0x80) == 0x00 {
        Ok((v as u64, bytes))
    } else if (v & 0xC0) == 0x80 {
        let mut b2 = [0u8; 1];
        stream.read_exact(&mut b2).await?;
        bytes.push(b2[0]);
        Ok((((v as u64 & 0x3F) << 8) | b2[0] as u64, bytes))
    } else if (v & 0xE0) == 0xC0 {
        let mut b2 = [0u8; 2];
        stream.read_exact(&mut b2).await?;
        bytes.extend_from_slice(&b2);
        Ok((
            ((v as u64 & 0x1F) << 16) | ((b2[0] as u64) << 8) | b2[1] as u64,
            bytes,
        ))
    } else if (v & 0xF0) == 0xE0 {
        let mut b2 = [0u8; 3];
        stream.read_exact(&mut b2).await?;
        bytes.extend_from_slice(&b2);
        Ok((
            ((v as u64 & 0x0F) << 24)
                | ((b2[0] as u64) << 16)
                | ((b2[1] as u64) << 8)
                | b2[2] as u64,
            bytes,
        ))
    } else if (v & 0xFC) == 0xF0 {
        let mut b2 = [0u8; 4];
        stream.read_exact(&mut b2).await?;
        bytes.extend_from_slice(&b2);
        Ok((
            ((b2[0] as u64) << 24) | ((b2[1] as u64) << 16) | ((b2[2] as u64) << 8) | b2[3] as u64,
            bytes,
        ))
    } else {
        Ok((v as u64, bytes))
    }
}

fn encode_message(buf: &mut Vec<u8>, msg_type: u16, payload: &[u8]) {
    buf.extend_from_slice(&msg_type.to_be_bytes());
    // Most Mumble clients expect a standard 32-bit BE length for ALL messages over TCP/TLS
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
}

async fn read_varint(stream: &mut TlsStream<TcpStream>) -> Result<u64, std::io::Error> {
    let mut b = [0u8; 1];
    stream.read_exact(&mut b).await?;
    let v = b[0];

    if (v & 0x80) == 0x00 {
        Ok(v as u64)
    } else if (v & 0xC0) == 0x80 {
        let mut b2 = [0u8; 1];
        stream.read_exact(&mut b2).await?;
        Ok(((v as u64 & 0x3F) << 8) | b2[0] as u64)
    } else if (v & 0xE0) == 0xC0 {
        let mut b2 = [0u8; 2];
        stream.read_exact(&mut b2).await?;
        Ok(((v as u64 & 0x1F) << 16) | ((b2[0] as u64) << 8) | b2[1] as u64)
    } else if (v & 0xF0) == 0xE0 {
        let mut b2 = [0u8; 3];
        stream.read_exact(&mut b2).await?;
        Ok(((v as u64 & 0x0F) << 24)
            | ((b2[0] as u64) << 16)
            | ((b2[1] as u64) << 8)
            | b2[2] as u64)
    } else if (v & 0xFC) == 0xF0 {
        let mut b2 = [0u8; 4];
        stream.read_exact(&mut b2).await?;
        Ok(((b2[0] as u64) << 24) | ((b2[1] as u64) << 16) | ((b2[2] as u64) << 8) | b2[3] as u64)
    } else if (v & 0xFC) == 0xF4 {
        let mut b2 = [0u8; 8];
        stream.read_exact(&mut b2).await?;
        let mut val = 0u64;
        for i in 0..8 {
            val = (val << 8) | b2[i] as u64;
        }
        Ok(val)
    } else {
        Ok(v as u64)
    }
}

fn encode_varint(val: u64) -> Vec<u8> {
    if val < 0x80 {
        vec![val as u8]
    } else if val < 0x4000 {
        vec![((val >> 8) as u8) | 0x80, (val & 0xFF) as u8]
    } else if val < 0x200000 {
        vec![
            ((val >> 16) as u8) | 0xC0,
            ((val >> 8) & 0xFF) as u8,
            (val & 0xFF) as u8,
        ]
    } else if val < 0x10000000 {
        vec![
            ((val >> 24) as u8) | 0xE0,
            ((val >> 16) & 0xFF) as u8,
            ((val >> 8) & 0xFF) as u8,
            (val & 0xFF) as u8,
        ]
    } else if val < 0x100000000 {
        vec![
            0xF0,
            ((val >> 24) & 0xFF) as u8,
            ((val >> 16) & 0xFF) as u8,
            ((val >> 8) & 0xFF) as u8,
            (val & 0xFF) as u8,
        ]
    } else {
        let mut res = vec![0xF4];
        res.extend_from_slice(&val.to_be_bytes());
        res
    }
}

/// Encode a value as a protobuf varint (LEB128).
/// This is different from Mumble's custom varint encoding above.
/// Protobuf uses 7 bits per byte with MSB as continuation bit.
fn encode_protobuf_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        if val < 0x80 {
            buf.push(val as u8);
            break;
        }
        buf.push((val as u8 & 0x7F) | 0x80);
        val >>= 7;
    }
}

fn encode_msg_vec(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();
    res.extend_from_slice(&msg_type.to_be_bytes());
    res.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    res.extend_from_slice(payload);
    res
}

async fn write_message(
    stream: &mut TlsStream<TcpStream>,
    msg_type: u16,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let msg = encode_msg_vec(msg_type, payload);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_client(
    mut stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    welcome: &str,
    state: Arc<ServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Handshake: Version
    let (msg_type, payload) = read_message(&mut stream).await?;
    if msg_type != MSG_VERSION {
        return Err("Expected Version".into());
    }
    let _client_version = mumble::Version::decode(&payload[..])?;

    let server_version = mumble::Version {
        version: Some(0x00010500),
        release: Some("CMT-IPAS 1.0.1".to_string()),
        os: Some("CMT".to_string()),
        os_version: Some("1.0".to_string()),
        ..Default::default()
    };
    write_message(&mut stream, MSG_VERSION, &server_version.encode_to_vec()).await?;

    // 3. Handshake: Authenticate
    let (msg_type, payload) = read_message(&mut stream).await?;
    if msg_type != MSG_AUTHENTICATE {
        return Err("Expected Authenticate".into());
    }
    let auth = mumble::Authenticate::decode(&payload[..])?;
    info!(
        "Client '{}' authenticating (Opus: {:?}, CELT: {:?})",
        auth.username.as_deref().unwrap_or("unknown"),
        auth.opus,
        auth.celt_versions
    );
    let username = auth.username.unwrap_or_else(|| "Anonymous".to_string());

    // --- DUPLICATE CHECK: Kick old session with same name ---
    let mut old_session_to_remove = None;
    for entry in state.clients.iter() {
        if entry.value().username == username {
            old_session_to_remove = Some(*entry.key());
            break;
        }
    }
    if let Some(old_id) = old_session_to_remove {
        info!(
            "Kicking duplicate session {} for user '{}'",
            old_id, username
        );
        state.clients.remove(&old_id);
        // The old task will eventually cleanup when it tries to send/receive
    }

    // --- LICENSE CHECK: User Limit ---
    let is_reg = state.is_registered.load(Ordering::SeqCst);
    let max_u = state.max_users.load(Ordering::SeqCst);

    if !is_reg && state.clients.len() >= 3 {
        let reject = mumble::Reject {
            r#type: Some(1),
            reason: Some("TRIAL LIMIT REACHED (3 USERS MAX). Please register.".to_string()),
        };
        write_message(&mut stream, MSG_REJECT, &reject.encode_to_vec()).await?;
        return Err("Trial user limit reached".into());
    } else if is_reg && max_u > 0 && state.clients.len() >= max_u as usize {
        let reject = mumble::Reject {
            r#type: Some(1),
            reason: Some(format!("LICENSE LIMIT REACHED ({} USERS MAX).", max_u)),
        };
        write_message(&mut stream, MSG_REJECT, &reject.encode_to_vec()).await?;
        return Err("License user limit reached".into());
    }

    // --- REGISTER CLIENT ---
    let session_id = state.next_session_id.fetch_add(1, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let client = Arc::new(Client {
        session_id,
        username: username.clone(),
        current_channel: std::sync::atomic::AtomicU32::new(0), // Start in Root
        tx,
    });
    // 5. Session Setup: Broadcast my presence and learn about others
    let my_chan = client.current_channel.load(Ordering::SeqCst);

    // Tell others about ME
    let my_state = mumble::UserState {
        session: Some(session_id),
        name: Some(username.clone()),
        channel_id: Some(my_chan),
        actor: Some(session_id),
        ..Default::default()
    };
    let my_state_msg = encode_msg_vec(MSG_USER_STATE, &my_state.encode_to_vec());

    for entry in state.clients.iter() {
        let other_id = entry.key();
        let other_client = entry.value();

        if *other_id != session_id {
            // Send ME to them
            let _ = other_client.tx.send(my_state_msg.clone());

            // Send THEM to me
            let other_state = mumble::UserState {
                session: Some(*other_id),
                name: Some(other_client.username.clone()),
                channel_id: Some(other_client.current_channel.load(Ordering::SeqCst)),
                actor: Some(*other_id),
                ..Default::default()
            };
            let _ = client
                .tx
                .send(encode_msg_vec(MSG_USER_STATE, &other_state.encode_to_vec()));
        }
    }

    // Add me to the active clients list
    state.clients.insert(session_id, client.clone());

    info!(
        "✅ Client '{}' (session={}) joined from {}",
        username, session_id, peer_addr
    );

    // ── Send all channels so client can see the room list ───────────
    for entry in state.channels.iter() {
        let ch_id = *entry.key();
        let ch_name = entry.value().clone();
        let ch_state = mumble::ChannelState {
            channel_id: Some(ch_id),
            parent: Some(0), // All sub-channels are under Root
            name: Some(ch_name),
            ..Default::default()
        };
        write_message(&mut stream, MSG_CHANNEL_STATE, &ch_state.encode_to_vec()).await?;
    }

    // ── Send OUR OWN UserState directly to ourselves first ──────────
    // CRITICAL: The client MUST receive its own UserState or it will disconnect.
    // We bypass the broadcast (which is blocked in Root by Isolation Mode).
    let my_state = mumble::UserState {
        session: Some(session_id),
        name: Some(username.clone()),
        channel_id: Some(0),
        ..Default::default()
    };
    write_message(&mut stream, MSG_USER_STATE, &my_state.encode_to_vec()).await?;

    // ── Tell everyone else about US (Isolation: blocked in Root = ch.0) ─
    state.broadcast_to_channel(
        0,
        MSG_USER_STATE,
        &my_state.encode_to_vec(),
        Some(session_id),
    );

    // Tell US about everyone else in the SAME channel
    for entry in state.clients.iter() {
        let other = entry.value();
        if other.session_id != session_id {
            let other_chan = other.current_channel.load(Ordering::SeqCst);
            if other_chan != 0 {
                let other_state = mumble::UserState {
                    session: Some(other.session_id),
                    name: Some(other.username.clone()),
                    channel_id: Some(other_chan),
                    ..Default::default()
                };
                write_message(&mut stream, MSG_USER_STATE, &other_state.encode_to_vec()).await?;
            }
        }
    }

    // ── CRITICAL: CryptSetup MUST be sent BEFORE ServerSync ─────────
    // Mumble clients consider handshake complete upon receiving ServerSync.
    // If CryptSetup/CodecVersion arrive after, the audio subsystem won't initialize.
    let crypt_setup = mumble::CryptSetup {
        key: Some(vec![0x42; 16]),
        client_nonce: Some(vec![0x42; 16]),
        server_nonce: Some(vec![0x42; 16]),
    };
    write_message(&mut stream, MSG_CRYPT_SETUP, &crypt_setup.encode_to_vec()).await?;

    // CodecVersion: Force Opus - must also be before ServerSync
    let codec_version = mumble::CodecVersion {
        alpha: -2147483637, // 0x8000000b
        beta: -2147483637,
        prefer_alpha: true,
        opus: Some(true),
    };
    write_message(
        &mut stream,
        MSG_CODEC_VERSION,
        &codec_version.encode_to_vec(),
    )
    .await?;

    // ServerConfig
    let server_config = mumble::ServerConfig {
        welcome_text: Some(welcome.to_string()),
        ..Default::default()
    };
    write_message(
        &mut stream,
        MSG_SERVER_CONFIG,
        &server_config.encode_to_vec(),
    )
    .await?;

    // ServerSync: This MUST be last - client considers handshake complete here
    let server_sync = mumble::ServerSync {
        session: Some(session_id),
        max_bandwidth: Some(72000),
        welcome_text: Some(welcome.to_string()),
        permissions: Some(0x07FFFFFF),
        ..Default::default()
    };
    write_message(&mut stream, MSG_SERVER_SYNC, &server_sync.encode_to_vec()).await?;

    // --- SPLIT STREAM: Separate read/write to avoid select! cancellation ---
    // tokio::select! can cancel read_message mid-read, losing bytes from the
    // TLS stream and corrupting all subsequent messages. By splitting into
    // separate tasks, reads and writes never interfere with each other.
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    // Writer task: handles ALL outgoing data (broadcasts + ping responses)
    let writer_tx = client.tx.clone();
    let write_session = session_id;
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_half.write_all(&msg).await {
                warn!("Writer error for session {}: {}", write_session, e);
                break;
            }
            if let Err(e) = write_half.flush().await {
                warn!("Flush error for session {}: {}", write_session, e);
                break;
            }
        }
    });

    // Reader loop: handles ALL incoming data (no select!, no cancellation risk)
    let read_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        loop {
            let (msg_type, payload) = read_message_generic(&mut read_half).await?;
            let my_chan = client.current_channel.load(Ordering::SeqCst);

            if msg_type == MSG_PING {
                // Route ping response through writer task
                let _ = writer_tx.send(encode_msg_vec(MSG_PING, &payload));
            } else {
                if msg_type != MSG_UDP_TUNNEL {
                    trace!(
                        "Received message type {} (len: {}) from session {}",
                        msg_type,
                        payload.len(),
                        session_id
                    );
                }

                if msg_type == MSG_UDP_TUNNEL {
                    if payload.len() > 1 {
                        let pkt_type = payload[0];

                        if pkt_type == 0x00 {
                            // ── Mumble 1.5+ Protobuf Audio Format ──────────
                            let mut relayed = Vec::with_capacity(payload.len() + 6);
                            relayed.push(0x00);
                            relayed.push(0x18); // Protobuf: field 3 (sender_session), varint
                            encode_protobuf_varint(&mut relayed, session_id as u64);
                            relayed.extend_from_slice(&payload[1..]);

                            state.broadcast_to_channel(
                                my_chan,
                                MSG_UDP_TUNNEL,
                                &relayed,
                                Some(session_id),
                            );
                        } else if pkt_type == 0x01 {
                            // Mumble 1.5 Ping packet - ignore
                        } else {
                            // ── Legacy Format (Mumble ≤1.4) ────────────────
                            let sid_bytes = encode_varint(session_id as u64);
                            let mut relayed =
                                Vec::with_capacity(1 + sid_bytes.len() + payload.len() - 1);
                            relayed.push(pkt_type);
                            relayed.extend_from_slice(&sid_bytes);
                            relayed.extend_from_slice(&payload[1..]);

                            state.broadcast_to_channel(
                                my_chan,
                                MSG_UDP_TUNNEL,
                                &relayed,
                                Some(session_id),
                            );
                        }
                    }
                } else if msg_type == MSG_USER_STATE {
                    if let Ok(mut new_state) = mumble::UserState::decode(&payload[..]) {
                        let mut full_payload = payload.clone();
                        if let Some(new_chan) = new_state.channel_id {
                            client.current_channel.store(new_chan, Ordering::SeqCst);

                            if new_state.name.is_none() {
                                new_state.name = Some(client.username.clone());
                                new_state.session = Some(session_id);
                                full_payload = new_state.encode_to_vec();
                            }
                        }
                        state.broadcast_global(MSG_USER_STATE, &full_payload, None);
                    }
                }
            }
        }
    }
    .await;

    // Cleanup
    writer.abort();
    state.clients.remove(&session_id);
    let remove_msg = mumble::UserRemove {
        session: session_id,
        ..Default::default()
    };
    state.broadcast_global(MSG_USER_REMOVE, &remove_msg.encode_to_vec(), None);

    match read_result {
        Ok(()) => Ok(()),
        Err(e) => {
            let err_msg = e.to_string();
            if !err_msg.contains("close_notify")
                && !err_msg.contains("unexpected EOF")
                && !err_msg.contains("Connection closed")
            {
                warn!(
                    "Client {} (session={}) connection error: {}",
                    client.username, session_id, err_msg
                );
            } else {
                info!(
                    "Client {} (session={}) disconnected",
                    client.username, session_id
                );
            }
            Err(e)
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initial Setup (Logging, Config, DB)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let args = Args::parse();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        "cmt_ipas=info,rustls=error,sqlx=error,h2=error,tower_http=error".into()
    });

    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(true)
        .init();

    let config_content = fs::read_to_string(&args.config).expect("Failed to read config file");
    let config: Config = toml::from_str(&config_content).expect("Failed to parse config file");

    let state = Arc::new(ServerState::new());

    use colored::Colorize;
    println!("╔══════════════════════════════════════════════╗");
    println!("║   {}         ║", "CMT-IPAS: Industrial Audio Gateway".cyan().bold());
    println!("║   {}                             ║", format!("Version: {}", env!("CARGO_PKG_VERSION")).yellow());
    let is_reg = state.is_registered.load(Ordering::SeqCst);
    let max_u = state.max_users.load(Ordering::SeqCst);
    if is_reg {
        let limit_str = if max_u == 0 { "UNLIMITED".to_string() } else { format!("{} USERS", max_u) };
        println!("║   {}                   ║", format!("[REGISTERED - {}]", limit_str).green().bold());
    } else {
        println!("║   {}                    ║", "[TRIAL - LIMIT 3 USERS]".red().bold());
    }
    println!("║   {}             ║", "(c) Chiangmai Micro Technology".blue());
    println!("╚══════════════════════════════════════════════╝");

    // 2. Start Tokio Runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let config_clone = toml::from_str::<Config>(&config_content).unwrap();
    let state_clone = state.clone();
    let args_clone = Args::parse();
    
    let db_pool = rt.block_on(async {
        let pool = db::init_db("ipas.db").await.expect("Failed to init DB");
        db::seed_admin(&pool, "admin", "password123").await.expect("Failed to seed admin");
        pool
    });

    let db_clone = db_pool.clone();
    rt.spawn(async move {
        if let Err(e) = run_server(args_clone, config_clone, state_clone, db_clone).await {
            error!("Server error: {}", e);
        }
    });

    // 3. GUI Event Loop
    let event_loop: tao::event_loop::EventLoop<()> = EventLoopBuilder::new().build();
    let tray_menu = Menu::new();
    let dashboard_item = MenuItem::new("🌍 Open Dashboard", true, None);
    let quit_item = MenuItem::new("❌ Exit", true, None);
    
    tray_menu.append_items(&[
        &dashboard_item,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ])?;

    let icon = if std::path::Path::new("assets/icon.png").exists() {
        load_icon(std::path::Path::new("assets/icon.png"))
    } else {
        Icon::from_rgba(vec![0, 120, 215, 255].repeat(32 * 32), 32, 32).unwrap()
    };

    let mut _tray_icon = Some(
        TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu))
            .with_tooltip("CMT-IPAS Audio Server")
            .with_icon(icon)
            .build()?,
    );

    let menu_channel = MenuEvent::receiver();

    event_loop.run(move |_event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Ok(event) = menu_channel.try_recv() {
            if event.id == dashboard_item.id() {
                let url = format!("http://127.0.0.1:{}", config.server.ws_port);
                #[cfg(target_os = "windows")]
                let _ = std::process::Command::new("cmd").args(["/C", "start", &url]).spawn();
                #[cfg(target_os = "macos")]
                let _ = std::process::Command::new("open").arg(&url).spawn();
                #[cfg(target_os = "linux")]
                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
            } else if event.id == quit_item.id() {
                *control_flow = ControlFlow::Exit;
            }
        }
    });

    Ok(())
}
