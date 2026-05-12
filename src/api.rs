use axum::{
    routing::{get, post, delete},
    Router, Json, extract::{State, Request, Path},
    http::StatusCode,
    response::IntoResponse,
    middleware::{self, Next},
};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use tracing::{info, error, warn, trace};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use bcrypt::{verify, hash, DEFAULT_COST};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::ServerState;
use prost::Message as ProstMessage;

// JWT Secret - In production, this should be in config/env
const JWT_SECRET: &[u8] = b"cmt-ipas-ultra-secure-secret-2026";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,      // username
    pub role: String,     // user role
    pub exp: usize,       // expiration time
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct PasswordChangeRequest {
    pub new_password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub must_change_password: bool,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct ApiKeyResponse {
    pub id: i64,
    pub name: String,
    pub key: Option<String>, // Only returned once on creation
    pub is_enabled: bool,
}

#[derive(Serialize)]
pub struct ProfileResponse {
    pub username: String,
    pub role: String,
    pub callsign: Option<String>,
}

#[derive(Deserialize)]
pub struct ProfileUpdateRequest {
    pub callsign: Option<String>,
}

pub struct AppState {
    pub db: Pool<Sqlite>,
    pub server: Arc<ServerState>,
}

#[derive(Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct MoveUserRequest {
    pub channel_id: u32,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct InviteUserRequest {
    pub channel_id: u32,
    pub username: String,
}

#[derive(Serialize)]
pub struct ChannelResponse {
    pub id: u32,
    pub name: String,
    pub has_password: bool,
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    pub session_id: u32,
    pub username: String,
    pub callsign: Option<String>,
    pub channel_id: u32,
}

#[derive(Serialize)]
pub struct HwidResponse {
    pub hwid: String,
}

#[derive(Serialize)]
pub struct NodeLocationResponse {
    pub callsign: String,
    pub lat: f64,
    pub lon: f64,
    pub alt: f64,
    pub status_code: i32,
    pub last_seen: String,
}

#[derive(Serialize)]
pub struct UserFullResponse {
    pub username: String,
    pub callsign: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminCreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
    pub callsign: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminUpdateUserRequest {
    pub password: Option<String>,
    pub role: Option<String>,
    pub callsign: Option<String>,
}

#[derive(Deserialize)]
pub struct ActivateLicenseRequest {
    pub license_hex: String,
}

pub async fn start_api_server(db_pool: Pool<Sqlite>, server_state: Arc<ServerState>, port: u16) {
    let shared_state = Arc::new(AppState { db: db_pool, server: server_state });

    // Public routes (No Auth required)
    let public_routes = Router::new()
        .route("/login", post(login_handler))
        .route("/license/hwid", get(get_hwid_handler));

    // Protected routes (Require JWT or API Key)
    let protected_routes = Router::new()
        .route("/users", get(list_users).post(admin_create_user))
        .route("/users/:username", post(admin_update_user).delete(admin_delete_user))
        .route("/password-change", post(password_change_handler))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/:id/toggle", post(toggle_api_key))
        .route("/profile", get(get_profile).post(update_profile))
        .route("/channels", get(list_channels).post(create_channel_handler))
        .route("/channels/:id", post(update_channel_handler))
        .route("/channels/:id/invitations", post(invite_user_handler).get(list_invitations))
        .route("/channels/:id/invitations/:username", delete(delete_invitation))
        .route("/channels/:source_id/invite-to/:target_id", post(invite_channel_to_channel))
        .route("/users/:username/invitations", get(get_user_invitations))
        .route("/sessions", get(list_sessions))
        .route("/sessions/:session_id/move", post(move_user_handler))
        .route("/channels/:id/users", get(get_users_by_channel))
        .route("/license/activate", post(activate_license_handler))
        .route("/nodes/locations", get(list_node_locations))
        .route("/mqtt-devices", get(list_mqtt_devices).post(create_mqtt_device))
        .route("/mqtt-devices/:id", post(update_mqtt_device).delete(delete_mqtt_device))
        .route("/mqtt/request-subscriptions", post(request_mqtt_subscriptions))
        .route("/subscriptions", post(create_subscription))
        .route("/subscriptions/:username", get(list_user_subscriptions))
        .route("/topics", get(list_topics))
        .route("/topics/:id", delete(delete_topic))
        .layer(middleware::from_fn_with_state(shared_state.clone(), auth_middleware));

    // Static file serving for Web Admin Panel
    let static_files = tower_http::services::ServeDir::new("web")
        .append_index_html_on_directories(true);

    let app = Router::new()
        .nest("/api/v1/auth", public_routes.merge(protected_routes))
        .fallback_service(static_files)
        .with_state(shared_state);

    let addr = format!("0.0.0.0:{}", port);
    info!("Starting REST API on http://{}", addr);
    info!("Admin Panel available at http://{}/", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> axum::response::Response {
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let mut jwt_claims = None;

    if let Some(auth_header) = auth_header {
        if auth_header.starts_with("Bearer ") {
            let token = &auth_header[7..];
            let validation = Validation::default();
            
            if let Ok(data) = decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &validation) {
                jwt_claims = Some(data.claims);
            }
        }
    }

    if let Some(claims) = jwt_claims {
        let mut req = req;
        req.extensions_mut().insert(claims);
        return next.run(req).await;
    }

    // 2. Check for API Key (X-API-Key Header)
    let x_api_key = req.headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok());

    if let Some(api_key) = x_api_key {
        let keys: Vec<(i64, String, String)> = sqlx::query_as("SELECT id, name, key_hash FROM api_keys WHERE is_enabled = 1")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

        for (_id, name, hash) in keys {
            if verify(api_key, &hash).unwrap_or(false) {
                let claims = Claims {
                    sub: format!("app:{}", name),
                    role: "API-App".into(),
                    exp: 0,
                };
                let mut req = req;
                req.extensions_mut().insert(claims);
                return next.run(req).await;
            }
        }
    }

    (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Invalid or missing token/API key".into() })).into_response()
}

#[derive(Serialize)]
pub struct MqttDeviceResponse {
    pub id: i64,
    pub username: String,
    pub is_enabled: bool,
    pub comment: Option<String>,
}

#[derive(Serialize)]
pub struct SubscriptionResponse {
    pub id: i64,
    pub username: String,
    pub topic: String,
    pub qos: i64,
    pub last_payload: Option<String>,
    pub last_updated: String,
}

#[derive(Deserialize)]
pub struct CreateMqttDeviceRequest {
    pub username: String,
    pub password: String,
    pub comment: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateMqttDeviceRequest {
    pub is_enabled: Option<bool>,
    pub comment: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateSubscriptionRequest {
    pub username: String,
    pub topic: String,
    pub qos: Option<i64>,
    pub payload: Option<String>,
}

#[derive(Deserialize)]
pub struct RequestSubscriptionRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct TopicResponse {
    pub id: i64,
    pub topic: String,
    pub last_payload: Option<String>,
    pub last_updated: String,
}

async fn create_api_key(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;

    // Generate a random 32-char key
    let raw_key: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let hashed = match hash(&raw_key, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Hashing failed").into_response(),
    };

    match sqlx::query("INSERT INTO api_keys (name, key_hash) VALUES (?, ?)")
        .bind(&payload.name)
        .bind(hashed)
        .execute(&state.db)
        .await
    {
        Ok(res) => {
            let id = res.last_insert_rowid();
            (StatusCode::CREATED, Json(ApiKeyResponse {
                id,
                name: payload.name,
                key: Some(raw_key),
                is_enabled: true,
            })).into_response()
        }
        Err(e) => {
            error!("DB error creating API key: {}", e);
            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Key name already exists".into() })).into_response()
        }
    }
}

async fn list_api_keys(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let keys: Vec<(i64, String, i64)> = sqlx::query_as("SELECT id, name, is_enabled FROM api_keys")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let response: Vec<ApiKeyResponse> = keys.into_iter().map(|(id, name, enabled)| {
        ApiKeyResponse {
            id,
            name,
            key: None, // Never return hash
            is_enabled: enabled == 1,
        }
    }).collect();

    Json(response)
}

async fn toggle_api_key(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    match sqlx::query("UPDATE api_keys SET is_enabled = 1 - is_enabled WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // 1. Fetch user from DB
    let user: Result<(String, String, String, i64), _> = sqlx::query_as(
        "SELECT username, password_hash, role, must_change_password FROM users WHERE username = ?"
    )
    .bind(&payload.username)
    .fetch_one(&state.db)
    .await;

    match user {
        Ok((username, hash, role, must_change)) => {
            info!("Login attempt for '{}', payload pass len: {}, db hash len: {}", username, payload.password.len(), hash.len());
            // 2. Verify password
            if verify(&payload.password, &hash).unwrap_or(false) {
                info!("Password verified successfully for {}", username);
                // 3. Generate JWT
                let expiration = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 24 * 3600; // 24 hours

                let claims = Claims {
                    sub: username,
                    role: role.clone(),
                    exp: expiration as usize,
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(JWT_SECRET),
                )
                .unwrap();

                (StatusCode::OK, Json(serde_json::json!({
                    "token": token,
                    "role": role,
                    "must_change_password": must_change == 1
                }))).into_response()
            } else {
                info!("Password verification failed for {}", username);
                (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "Incorrect password verification failed".into() })).into_response()
            }
        }
        Err(e) => {
            (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: format!("DB Error: {:?}", e) })).into_response()
        }
    }
}

async fn password_change_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    Json(payload): Json<PasswordChangeRequest>,
) -> impl IntoResponse {
    let hashed = match hash(&payload.new_password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Hashing failed").into_response(),
    };

    match sqlx::query("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = ?")
        .bind(hashed)
        .bind(&claims.sub)
        .execute(&state.db)
        .await
    {
        Ok(_) => {
            info!("Password updated for user: {}", claims.sub);
            (StatusCode::OK, Json(StatusResponse { status: "success".into(), message: "Password changed successfully".into() })).into_response()
        }
        Err(e) => {
            error!("DB error updating password: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Database error".into() })).into_response()
        }
    }
}

async fn get_profile(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
) -> impl IntoResponse {
    let user: Result<(String, String, Option<String>), _> = sqlx::query_as(
        "SELECT username, role, callsign FROM users WHERE username = ?"
    )
    .bind(&claims.sub)
    .fetch_one(&state.db)
    .await;

    match user {
        Ok((username, role, callsign)) => (StatusCode::OK, Json(ProfileResponse { username, role, callsign })).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn update_profile(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    Json(payload): Json<ProfileUpdateRequest>,
) -> impl IntoResponse {
    match sqlx::query("UPDATE users SET callsign = ? WHERE username = ?")
        .bind(&payload.callsign)
        .bind(&claims.sub)
        .execute(&state.db)
        .await
    {
        Ok(_) => {
            info!("Profile callsign updated for user: {}", claims.sub);
            (StatusCode::OK, Json(StatusResponse { status: "success".into(), message: "Profile updated".into() })).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn list_users(State(state): State<Arc<AppState>>) -> Json<Vec<UserFullResponse>> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as("SELECT username, callsign FROM users")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    
    let users = rows.into_iter().map(|(u, c)| UserFullResponse { username: u, callsign: c }).collect();
    Json(users)
}

async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AdminCreateUserRequest>,
) -> impl IntoResponse {
    let hashed = match hash(&payload.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Hashing failed").into_response(),
    };

    match sqlx::query("INSERT INTO users (username, password_hash, role, callsign) VALUES (?, ?, ?, ?)")
        .bind(&payload.username)
        .bind(hashed)
        .bind(&payload.role)
        .bind(&payload.callsign)
        .execute(&state.db)
        .await
    {
        Ok(_) => {
            info!("Admin created user: {}", payload.username);
            (StatusCode::CREATED, Json(StatusResponse { status: "success".into(), message: "User created".into() })).into_response()
        }
        Err(e) => {
            error!("DB error creating user: {}", e);
            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "Username already exists".into() })).into_response()
        }
    }
}

async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    Json(payload): Json<AdminUpdateUserRequest>,
) -> impl IntoResponse {
    // 1. Update basic info
    if let Some(role) = payload.role {
        let _ = sqlx::query("UPDATE users SET role = ? WHERE username = ?")
            .bind(role).bind(&username).execute(&state.db).await;
    }
    
    if let Some(callsign) = payload.callsign {
        let _ = sqlx::query("UPDATE users SET callsign = ? WHERE username = ?")
            .bind(callsign).bind(&username).execute(&state.db).await;
    }

    // 2. Update password if provided
    if let Some(pwd) = payload.password {
        if !pwd.is_empty() {
            let hashed = hash(pwd, DEFAULT_COST).unwrap();
            let _ = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
                .bind(hashed).bind(&username).execute(&state.db).await;
        }
    }

    info!("Admin updated user: {}", username);
    (StatusCode::OK, Json(StatusResponse { status: "success".into(), message: "User updated".into() })).into_response()
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if username == "admin" {
        return (StatusCode::FORBIDDEN, Json(ErrorResponse { error: "Cannot delete master admin".into() })).into_response();
    }

    match sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(&username)
        .execute(&state.db)
        .await
    {
        Ok(_) => {
            info!("Admin deleted user: {}", username);
            (StatusCode::OK, Json(StatusResponse { status: "success".into(), message: "User deleted".into() })).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ── Channel Management Handlers ────────────────────────────────────

async fn list_channels(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<ChannelResponse>> {
    // Fetch channel passwords from database
    let channel_passwords: std::collections::HashMap<i64, Option<String>> = sqlx::query_as("SELECT id, password FROM channels")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

    let channels: Vec<ChannelResponse> = state.server.channels.iter()
        .map(|entry| {
            let ch_id = *entry.key() as i64;
            let has_password = channel_passwords.get(&ch_id)
                .and_then(|p| p.as_ref())
                .map(|p| !p.is_empty())
                .unwrap_or(false);
            ChannelResponse {
                id: *entry.key(),
                name: entry.value().clone(),
                has_password,
            }
        })
        .collect();
    Json(channels)
}

async fn create_channel_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateChannelRequest>,
) -> impl IntoResponse {
    if payload.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Channel name cannot be empty"}))).into_response();
    }
    let ch_id = state.server.create_channel(payload.name.clone());

    // TODO: Get current user from JWT token - for now use "admin" as default
    let owner = "admin".to_string();

    // Save to database
    if let Err(e) = sqlx::query("INSERT INTO channels (id, name, parent_id, password, owner) VALUES (?, ?, 0, ?, ?)")
        .bind(ch_id)
        .bind(&payload.name)
        .bind(&payload.password)
        .bind(&owner)
        .execute(&state.db)
        .await {
            error!("Failed to save channel to database: {}", e);
        }

    // Broadcast new channel to ALL connected clients
    let ch_msg = crate::mumble::ChannelState {
        channel_id: Some(ch_id),
        parent: Some(0),
        name: Some(payload.name.clone()),
        ..Default::default()
    };
    state.server.broadcast_global_raw(
        crate::MSG_CHANNEL_STATE,
        &ch_msg.encode_to_vec(),
        None,
    );

    info!("Admin created channel: '{}' (id={})", payload.name, ch_id);
    let has_password = payload.password.as_ref().map(|p| !p.is_empty()).unwrap_or(false);
    (StatusCode::CREATED, Json(ChannelResponse { id: ch_id, name: payload.name, has_password })).into_response()
}

async fn update_channel_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u32>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let password: Option<String> = payload.get("password").and_then(|p| p.as_str()).map(|s| s.to_string());

    // Update channel password in database
    if let Err(e) = sqlx::query("UPDATE channels SET password = ? WHERE id = ?")
        .bind(&password)
        .bind(id as i64)
        .execute(&state.db)
        .await {
            error!("Failed to update channel password: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to update channel password"}))).into_response();
        }

    info!("Admin updated password for channel id={}", id);
    (StatusCode::OK, Json(serde_json::json!({"success": true}))).into_response()
}

// ── Channel Invitations Handlers ───────────────────────────────────────
async fn invite_user_handler(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<u32>,
    Json(payload): Json<InviteUserRequest>,
) -> impl IntoResponse {
    // Check if channel exists and get owner
    let channel_info: Option<(String, Option<String>)> = sqlx::query_as("SELECT owner, password FROM channels WHERE id = ?")
        .bind(channel_id as i64)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    if channel_info.is_none() {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Channel not found"}))).into_response();
    }

    let (owner, _) = channel_info.unwrap();

    // Insert invitation (use INSERT OR IGNORE to handle duplicates)
    let _ = sqlx::query("INSERT OR IGNORE INTO channel_invitations (channel_id, username, invited_by) VALUES (?, ?, ?)")
        .bind(channel_id as i64)
        .bind(&payload.username)
        .bind(&owner)
        .execute(&state.db)
        .await;

    // Auto-move user to the channel
    let mut moved = false;
    for entry in state.server.clients.iter() {
        let client = entry.value();
        if client.username == payload.username {
            let old_chan = client.current_channel.load(std::sync::atomic::Ordering::SeqCst);
            client.current_channel.store(channel_id, std::sync::atomic::Ordering::SeqCst);

            // Send UserState update to ALL clients
            let user_state_msg = crate::mumble::UserState {
                session: Some(*entry.key()),
                channel_id: Some(channel_id),
                ..Default::default()
            };
            state.server.broadcast_global_raw(
                crate::MSG_USER_STATE,
                &user_state_msg.encode_to_vec(),
                None,
            );

            info!("Auto-moved user {} from channel {} to {}", payload.username, old_chan, channel_id);
            moved = true;
            break;
        }
    }

    info!("User {} invited to channel {} by {}", payload.username, channel_id, owner);
    (StatusCode::CREATED, Json(serde_json::json!({"success": true, "moved": moved}))).into_response()
}

async fn list_invitations(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<u32>,
) -> Json<serde_json::Value> {
    let invitations: Vec<(String, String, String)> = sqlx::query_as("SELECT username, invited_by, created_at FROM channel_invitations WHERE channel_id = ? ORDER BY created_at DESC")
        .bind(channel_id as i64)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    Json(serde_json::json!({
        "invitations": invitations.iter().map(|(username, invited_by, created_at)| {
            serde_json::json!({
                "username": username,
                "invited_by": invited_by,
                "created_at": created_at
            })
        }).collect::<Vec<_>>()
    }))
}

async fn delete_invitation(
    State(state): State<Arc<AppState>>,
    Path((channel_id, username)): Path<(u32, String)>,
) -> impl IntoResponse {
    if let Err(e) = sqlx::query("DELETE FROM channel_invitations WHERE channel_id = ? AND username = ?")
        .bind(channel_id as i64)
        .bind(&username)
        .execute(&state.db)
        .await {
            error!("Failed to delete invitation: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to delete invitation"}))).into_response();
        }

    info!("Invitation for {} to channel {} deleted", username, channel_id);
    (StatusCode::OK, Json(serde_json::json!({"success": true}))).into_response()
}

async fn get_user_invitations(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Json<serde_json::Value> {
    let invitations: Vec<(i64, String, String, String)> = sqlx::query_as("SELECT ci.channel_id, ci.invited_by, ci.created_at, c.name FROM channel_invitations ci JOIN channels c ON ci.channel_id = c.id WHERE ci.username = ? ORDER BY ci.created_at DESC")
        .bind(&username)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    Json(serde_json::json!({
        "invitations": invitations.iter().map(|(channel_id, invited_by, created_at, channel_name)| {
            serde_json::json!({
                "channel_id": channel_id,
                "channel_name": channel_name,
                "invited_by": invited_by,
                "created_at": created_at
            })
        }).collect::<Vec<_>>()
    }))
}

async fn invite_channel_to_channel(
    State(state): State<Arc<AppState>>,
    Path((source_id, target_id)): Path<(u32, u32)>,
) -> impl IntoResponse {
    // Get users from source channel and move them to target channel
    let mut invited_count = 0;
    let mut failed_count = 0;

    for entry in state.server.clients.iter() {
        let client = entry.value();
        let current_channel = client.current_channel.load(std::sync::atomic::Ordering::SeqCst);

        if current_channel == source_id {
            // Invite this user to target channel
            if let Err(e) = sqlx::query("INSERT OR IGNORE INTO channel_invitations (channel_id, username, invited_by) VALUES (?, ?, ?)")
                .bind(target_id as i64)
                .bind(&client.username)
                .bind("admin")
                .execute(&state.db)
                .await {
                    error!("Failed to invite user {} to channel {}: {}", client.username, target_id, e);
                    failed_count += 1;
                } else {
                    invited_count += 1;

                    // Auto-move user to target channel
                    client.current_channel.store(target_id, std::sync::atomic::Ordering::SeqCst);

                    // Send UserState update to ALL clients
                    let user_state_msg = crate::mumble::UserState {
                        session: Some(*entry.key()),
                        channel_id: Some(target_id),
                        ..Default::default()
                    };
                    state.server.broadcast_global_raw(
                        crate::MSG_USER_STATE,
                        &user_state_msg.encode_to_vec(),
                        None,
                    );

                    info!("Auto-moved user {} from channel {} to {}", client.username, source_id, target_id);
                }
        }
    }

    info!("Invited and moved {} users from channel {} to channel {} ({} failed)", invited_count, source_id, target_id, failed_count);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "invited_count": invited_count,
        "failed_count": failed_count
    }))).into_response()
}

// ── Session Management Handlers ────────────────────────────────────

async fn list_sessions(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<UserInfoResponse>> {
    let mut response = Vec::new();

    for entry in state.server.clients.iter() {
        let client = entry.value();

        // Fetch callsign from DB for this user
        let callsign: Option<String> = sqlx::query_scalar("SELECT callsign FROM users WHERE username = ?")
            .bind(&client.username)
            .fetch_optional(&state.db)
            .await
            .unwrap_or_default()
            .flatten();

        response.push(UserInfoResponse {
            session_id: *entry.key(),
            username: client.username.clone(),
            channel_id: client.current_channel.load(std::sync::atomic::Ordering::SeqCst),
            callsign,
        });
    }
    Json(response)
}

async fn get_users_by_channel(
    State(state): State<Arc<AppState>>,
    Path(channel_id): Path<u32>,
) -> Json<Vec<UserInfoResponse>> {
    let mut response = Vec::new();

    for entry in state.server.clients.iter() {
        let client = entry.value();
        let current_channel = client.current_channel.load(std::sync::atomic::Ordering::SeqCst);

        if current_channel == channel_id {
            let callsign: Option<String> = sqlx::query_scalar("SELECT callsign FROM users WHERE username = ?")
                .bind(&client.username)
                .fetch_optional(&state.db)
                .await
                .unwrap_or_default()
                .flatten();

            response.push(UserInfoResponse {
                session_id: *entry.key(),
                username: client.username.clone(),
                channel_id: current_channel,
                callsign,
            });
        }
    }
    Json(response)
}

async fn move_user_handler(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<u32>,
    Json(payload): Json<MoveUserRequest>,
) -> impl IntoResponse {
    // Validate channel exists
    if !state.server.channels.contains_key(&payload.channel_id) {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("Channel {} does not exist", payload.channel_id)
        }))).into_response();
    }

    // Check if channel has password and validate it
    let channel_password: Option<String> = sqlx::query_scalar("SELECT password FROM channels WHERE id = ?")
        .bind(payload.channel_id as i64)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    if channel_password.as_ref().map(|p| !p.is_empty()).unwrap_or(false) {
        // Channel has password, check if user is invited
        let client_username = if let Some(c) = state.server.clients.get(&session_id) {
            c.username.clone()
        } else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "error": format!("Session {} not found", session_id)
            }))).into_response();
        };

        let is_invited: bool = sqlx::query_scalar("SELECT COUNT(*) FROM channel_invitations WHERE channel_id = ? AND username = ?")
            .bind(payload.channel_id as i64)
            .bind(&client_username)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0) > 0;

        // If not invited, check password
        if !is_invited && payload.password.as_deref() != channel_password.as_deref() {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({
                "error": "Incorrect channel password"
            }))).into_response();
        }
    }

    // Find the client
    if let Some(client) = state.server.clients.get(&session_id) {
        let old_chan = client.current_channel.load(std::sync::atomic::Ordering::SeqCst);
        client.current_channel.store(payload.channel_id, std::sync::atomic::Ordering::SeqCst);

        // Send UserState update to ALL clients so everyone sees the move
        let user_state_msg = crate::mumble::UserState {
            session: Some(session_id),
            channel_id: Some(payload.channel_id),
            ..Default::default()
        };
        state.server.broadcast_global_raw(
            crate::MSG_USER_STATE,
            &user_state_msg.encode_to_vec(),
            None,
        );

        info!("Admin moved session={} '{}' from ch={} to ch={}",
            session_id, client.username, old_chan, payload.channel_id);

        (StatusCode::OK, Json(serde_json::json!({
            "session_id": session_id,
            "username": client.username,
            "moved_to_channel": payload.channel_id
        }))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("Session {} not found", session_id)
        }))).into_response()
    }
}

// ── License Management Handlers ────────────────────────────────────

async fn get_hwid_handler(
    State(state): State<Arc<AppState>>,
) -> Json<HwidResponse> {
    Json(HwidResponse {
        hwid: state.server.hwid.clone(),
    })
}

async fn activate_license_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ActivateLicenseRequest>,
) -> impl IntoResponse {
    use std::fs;
    
    // 1. Decode hex to bytes
    let bytes = match hex::decode(&payload.license_hex) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid hex format"}))).into_response(),
    };

    // 2. Save to license.dat
    if let Err(e) = fs::write("license.dat", bytes) {
        error!("Failed to write license.dat: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to save file"}))).into_response();
    }

    // 3. Reload license in ServerState
    state.server.reload_license();

    let is_reg = state.server.is_registered.load(std::sync::atomic::Ordering::SeqCst);
    let max_u = state.server.max_users.load(std::sync::atomic::Ordering::SeqCst);

    if is_reg {
        info!("License activated via API. Limit: {} users", max_u);
        (StatusCode::OK, Json(serde_json::json!({
            "status": "success",
            "message": "License activated successfully",
            "max_users": max_u
        }))).into_response()
    } else {
        warn!("License activation failed via API: Invalid or mismatched license file");
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "License verification failed (HWID mismatch or invalid signature)"
        }))).into_response()
    }
}

async fn list_node_locations(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let rows_result: Result<Vec<(String, f64, f64, f64, i64, String)>, _> = sqlx::query_as(
        "SELECT callsign, COALESCE(last_lat, 0.0), COALESCE(last_lon, 0.0), COALESCE(last_alt, 0.0), COALESCE(status_code, 0), COALESCE(CAST(last_seen_at AS TEXT), '') FROM nodes"
    )
    .fetch_all(&state.db)
    .await;

    let rows = match rows_result {
        Ok(r) => r,
        Err(e) => {
            error!("❌ Database error fetching node locations: {}", e);
            vec![]
        }
    };

    let response: Vec<NodeLocationResponse> = rows.into_iter().map(|(callsign, lat, lon, alt, status, seen)| {
        NodeLocationResponse {
            callsign,
            lat,
            lon,
            alt,
            status_code: status as i32,
            last_seen: seen,
        }
    }).collect();

    trace!("API: Returning {} node locations", response.len());
    Json(response)
}
// ── MQTT Device Handlers ───────────────────────────────────────────

async fn list_mqtt_devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rows: Vec<(i64, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, username, is_enabled, comment FROM mqtt_devices"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let devices: Vec<MqttDeviceResponse> = rows.into_iter().map(|(id, u, e, c)| MqttDeviceResponse {
        id,
        username: u,
        is_enabled: e == 1,
        comment: c,
    }).collect();

    Json(devices)
}

async fn create_mqtt_device(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateMqttDeviceRequest>,
) -> impl IntoResponse {
    let hashed = match hash(&payload.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    match sqlx::query("INSERT INTO mqtt_devices (username, password_hash, comment) VALUES (?, ?, ?)")
        .bind(&payload.username)
        .bind(hashed)
        .bind(&payload.comment)
        .execute(&state.db)
        .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "Username already exists").into_response(),
    }
}

async fn update_mqtt_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(payload): Json<UpdateMqttDeviceRequest>,
) -> impl IntoResponse {
    if let Some(enabled) = payload.is_enabled {
        let _ = sqlx::query("UPDATE mqtt_devices SET is_enabled = ? WHERE id = ?")
            .bind(if enabled { 1 } else { 0 })
            .bind(id)
            .execute(&state.db)
            .await;
    }

    if let Some(comment) = payload.comment {
        let _ = sqlx::query("UPDATE mqtt_devices SET comment = ? WHERE id = ?")
            .bind(comment)
            .bind(id)
            .execute(&state.db)
            .await;
    }

    if let Some(pwd) = payload.password {
        if !pwd.is_empty() {
            let hashed = hash(pwd, DEFAULT_COST).unwrap();
            let _ = sqlx::query("UPDATE mqtt_devices SET password_hash = ? WHERE id = ?")
                .bind(hashed)
                .bind(id)
                .execute(&state.db)
                .await;
        }
    }

    StatusCode::OK.into_response()
}

async fn delete_mqtt_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match sqlx::query("DELETE FROM mqtt_devices WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ── MQTT Subscription Handlers ─────────────────────────────────────────

async fn list_user_subscriptions(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let rows: Vec<(i64, String, String, i64, Option<String>, String)> = sqlx::query_as(
        "SELECT id, username, topic, qos, last_payload, last_updated FROM mqtt_subscriptions WHERE username = ?"
    )
    .bind(&username)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let subscriptions: Vec<SubscriptionResponse> = rows.into_iter().map(|(id, u, topic, qos, payload, updated)| {
        SubscriptionResponse {
            id,
            username: u,
            topic,
            qos,
            last_payload: payload,
            last_updated: updated,
        }
    }).collect();

    Json(subscriptions)
}

async fn create_subscription(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateSubscriptionRequest>,
) -> impl IntoResponse {
    match sqlx::query("
        INSERT INTO mqtt_subscriptions (username, topic, qos, last_payload)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(username, topic) DO UPDATE SET
            qos = excluded.qos,
            last_payload = excluded.last_payload,
            last_updated = CURRENT_TIMESTAMP
    ")
    .bind(&payload.username)
    .bind(&payload.topic)
    .bind(payload.qos.unwrap_or(0))
    .bind(&payload.payload)
    .execute(&state.db)
    .await
    {
        Ok(_) => {
            info!("Subscription created/updated: {} -> {}", payload.username, payload.topic);
            (StatusCode::OK, Json(StatusResponse { status: "success".into(), message: "Subscription saved".into() })).into_response()
        }
        Err(e) => {
            error!("Failed to save subscription: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to save subscription".into() })).into_response()
        }
    }
}

async fn request_mqtt_subscriptions(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RequestSubscriptionRequest>,
) -> impl IntoResponse {
    // For now, this is a placeholder
    // The actual MQTT broker (rumqttd) doesn't provide an API to query subscriptions
    // Devices must report their subscriptions to cmt/internal/subscriptions topic

    info!("Requesting subscription report from device: {}", payload.username);
    info!("Note: Device must be configured to report subscriptions to cmt/internal/subscriptions topic");

    (StatusCode::OK, Json(StatusResponse {
        status: "success".into(),
        message: format!("To enable auto-tracking, configure device {} to send subscriptions to cmt/internal/subscriptions", payload.username)
    })).into_response()
}

async fn list_topics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let rows = sqlx::query_as::<_, (i64, String, Option<String>, String)>("
        SELECT id, topic, last_payload, last_updated
        FROM mqtt_topics
        ORDER BY last_updated DESC
    ")
    .fetch_all(&state.db)
    .await;

    match rows {
        Ok(topics) => {
            let response: Vec<TopicResponse> = topics.into_iter().map(|(id, topic, payload, updated)| {
                TopicResponse {
                    id,
                    topic,
                    last_payload: payload,
                    last_updated: updated,
                }
            }).collect();
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            error!("Failed to fetch topics: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to fetch topics".into() })).into_response()
        }
    }
}

async fn delete_topic(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    match sqlx::query("DELETE FROM mqtt_topics WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await
    {
        Ok(_) => {
            info!("Topic deleted: {}", id);
            (StatusCode::OK, Json(StatusResponse { status: "success".into(), message: "Topic deleted".into() })).into_response()
        }
        Err(e) => {
            error!("Failed to delete topic: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "Failed to delete topic".into() })).into_response()
        }
    }
}
