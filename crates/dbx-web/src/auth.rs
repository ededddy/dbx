use std::sync::Arc;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::WebState;

#[derive(Deserialize)]
pub struct LoginRequest {
    /// Optional for backwards compatibility: old clients send only a
    /// password, which maps to the default "admin" account.
    pub username: Option<String>,
    pub password: String,
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    /// Optional: defaults to the session's user, then "admin".
    pub username: Option<String>,
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct AuthCheckResponse {
    pub authenticated: bool,
    pub required: bool,
    pub setup_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    /// True for host-provided env accounts, which cannot be managed here.
    pub managed_by_env: bool,
}

const MAX_ATTEMPTS: u32 = 5;
const LOCKOUT_SECS: u64 = 60;
const DEFAULT_USERNAME: &str = "admin";

fn session_cookie_path(state: &WebState) -> &str {
    state.public_base_path.as_str()
}

fn hash_password(password: &str) -> Result<String, StatusCode> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

fn normalize_username(username: Option<&str>) -> String {
    username.map(str::trim).filter(|u| !u.is_empty()).unwrap_or(DEFAULT_USERNAME).to_string()
}

/// True when at least one account (env-provided or in the users table) exists.
async fn has_any_account(state: &WebState) -> bool {
    !state.bootstrap_users.is_empty() || *state.has_db_users.read().await
}

/// Resolve the Argon2 hash for a username: env-provided accounts win over DB users.
async fn resolve_user_hash(state: &WebState, username: &str) -> Option<String> {
    if let Some(hash) = state.bootstrap_users.get(username) {
        return Some(hash.clone());
    }
    // The UNIQUE ... COLLATE NOCASE index keeps bootstrap usernames distinct in
    // practice; compare case-insensitively here to be safe.
    if state.bootstrap_users.keys().any(|u| u.eq_ignore_ascii_case(username)) {
        return None;
    }
    state.app.storage.load_user_by_username(username).await.ok().flatten().map(|u| u.password_hash)
}

async fn drop_sessions_for_user(state: &WebState, username: &str) {
    state.sessions.write().await.retain(|_, u| u != username);
}

pub async fn login(State(state): State<Arc<WebState>>, Json(body): Json<LoginRequest>) -> Result<Response, StatusCode> {
    if !has_any_account(&state).await {
        // No account configured yet — the client will proceed to setup.
        return Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response());
    }

    // Check rate limit
    {
        let rl = state.login_rate_limit.lock().await;
        if let Some(locked_until) = rl.locked_until {
            if locked_until > std::time::Instant::now() {
                let remaining = (locked_until - std::time::Instant::now()).as_secs();
                return Ok((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error": format!("Please try again in {remaining}s")})),
                )
                    .into_response());
            }
        }
    }

    let username = normalize_username(body.username.as_deref());
    let hash = resolve_user_hash(&state, &username).await;
    let verified = match hash.as_deref() {
        Some(hash) => verify_password(&body.password, hash),
        None => false,
    };

    if !verified {
        let mut rl = state.login_rate_limit.lock().await;
        rl.fail_count += 1;
        if rl.fail_count >= MAX_ATTEMPTS {
            rl.locked_until = Some(std::time::Instant::now() + std::time::Duration::from_secs(LOCKOUT_SECS));
            rl.fail_count = 0;
        }
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Success — reset rate limit
    {
        let mut rl = state.login_rate_limit.lock().await;
        rl.fail_count = 0;
        rl.locked_until = None;
    }

    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.write().await.insert(token.clone(), username);

    let cookie = format!("dbx_session={token}; Path={}; HttpOnly; SameSite=Lax", session_cookie_path(&state));
    Ok((StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn setup(State(state): State<Arc<WebState>>, Json(body): Json<SetupRequest>) -> Result<Response, StatusCode> {
    if state.password_disabled {
        return Err(StatusCode::FORBIDDEN);
    }

    // Only allow setup when no account exists yet
    if has_any_account(&state).await {
        return Err(StatusCode::FORBIDDEN);
    }

    let username = body.username.trim().to_string();
    if username.is_empty() || body.password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let hash = hash_password(&body.password)?;

    // Save to database
    state.app.storage.create_user(&username, &hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    *state.has_db_users.write().await = true;

    // Auto-login: create session
    let token = uuid::Uuid::new_v4().to_string();
    state.sessions.write().await.insert(token.clone(), username);

    let cookie = format!("dbx_session={token}; Path={}; HttpOnly; SameSite=Lax", session_cookie_path(&state));
    Ok((StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn check(State(state): State<Arc<WebState>>, req: Request<axum::body::Body>) -> Json<AuthCheckResponse> {
    if state.password_disabled {
        return Json(AuthCheckResponse { authenticated: true, required: false, setup_required: false, username: None });
    }
    if !has_any_account(&state).await {
        return Json(AuthCheckResponse { authenticated: false, required: false, setup_required: true, username: None });
    }
    let username = match extract_session_token(&req) {
        Some(token) => state.sessions.read().await.get(&token).cloned(),
        None => None,
    };
    Json(AuthCheckResponse { authenticated: username.is_some(), required: true, setup_required: false, username })
}

pub async fn change_password(
    State(state): State<Arc<WebState>>,
    req: Request<axum::body::Body>,
) -> Result<Response, StatusCode> {
    let session_user = match extract_session_token(&req) {
        Some(token) => state.sessions.read().await.get(&token).cloned(),
        None => None,
    };
    let body: ChangePasswordRequest = match axum::body::to_bytes(req.into_body(), 1024 * 16).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    if body.new_password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let username = match body.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => u.to_string(),
        None => session_user.unwrap_or_else(|| DEFAULT_USERNAME.to_string()),
    };

    // Env-provided accounts are managed by the host, not through the UI.
    if state.bootstrap_users.contains_key(&username) {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "This account's password is managed via environment variables"})),
        )
            .into_response());
    }

    let user = match state
        .app
        .storage
        .load_user_by_username(&username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(u) => u,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    if !verify_password(&body.old_password, &user.password_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_hash = hash_password(&body.new_password)?;
    state.app.storage.update_user_password(user.id, &new_hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn list_users(State(state): State<Arc<WebState>>) -> Result<Json<Vec<UserSummary>>, StatusCode> {
    let db_users = state.app.storage.list_users().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut users: Vec<UserSummary> = db_users
        .into_iter()
        .map(|u| UserSummary {
            id: Some(u.id),
            username: u.username,
            created_at: Some(u.created_at),
            managed_by_env: false,
        })
        .collect();
    for username in state.bootstrap_users.keys() {
        users.push(UserSummary { id: None, username: username.clone(), created_at: None, managed_by_env: true });
    }
    users.sort_by_key(|u| u.username.to_lowercase());
    Ok(Json(users))
}

pub async fn create_user(
    State(state): State<Arc<WebState>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<Response, StatusCode> {
    let username = body.username.trim().to_string();
    if username.is_empty() || body.password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if state.bootstrap_users.keys().any(|u| u.eq_ignore_ascii_case(&username)) {
        return Ok(
            (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Username already exists"}))).into_response()
        );
    }
    if state
        .app
        .storage
        .load_user_by_username(&username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Ok(
            (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Username already exists"}))).into_response()
        );
    }

    let hash = hash_password(&body.password)?;
    state.app.storage.create_user(&username, &hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    *state.has_db_users.write().await = true;

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn delete_user(
    State(state): State<Arc<WebState>>,
    Path(id): Path<i64>,
    req: Request<axum::body::Body>,
) -> Result<Response, StatusCode> {
    let session_user = match extract_session_token(&req) {
        Some(token) => state.sessions.read().await.get(&token).cloned(),
        None => None,
    };

    let users = state.app.storage.list_users().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(target) = users.iter().find(|u| u.id == id) else {
        return Err(StatusCode::NOT_FOUND);
    };

    if session_user.as_deref().is_some_and(|u| u.eq_ignore_ascii_case(&target.username)) {
        return Ok((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "You cannot delete your own account"})))
            .into_response());
    }
    if users.len() <= 1 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Cannot delete the last user account"})),
        )
            .into_response());
    }

    let username = target.username.clone();
    state.app.storage.delete_user(id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    *state.has_db_users.write().await = users.len() > 1;
    drop_sessions_for_user(&state, &username).await;

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn reset_user_password(
    State(state): State<Arc<WebState>>,
    Path(id): Path<i64>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<Response, StatusCode> {
    if body.password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let users = state.app.storage.list_users().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(target) = users.iter().find(|u| u.id == id) else {
        return Err(StatusCode::NOT_FOUND);
    };

    let hash = hash_password(&body.password)?;
    state.app.storage.update_user_password(id, &hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    drop_sessions_for_user(&state, &target.username).await;

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn logout(State(state): State<Arc<WebState>>, req: Request<axum::body::Body>) -> Response {
    if let Some(token) = extract_session_token(&req) {
        state.sessions.write().await.remove(&token);
        // 登出只清除当前登录会话的临时密码，不影响其他会话与桌面端凭据。
        state.app.session_credentials.clear_owner(&token);
    }
    let cookie = format!("dbx_session=; Path={}; HttpOnly; Max-Age=0", session_cookie_path(&state));
    (StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response()
}

pub fn session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("dbx_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_session_token<B>(req: &Request<B>) -> Option<String> {
    session_token_from_headers(req.headers())
}

fn api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = path.strip_prefix("/api/") {
        return Some(suffix);
    }
    let base = public_base_path.trim_end_matches('/');
    if base.is_empty() || base == "/" {
        return None;
    }
    path.strip_prefix(base)?.strip_prefix("/api/")
}

fn middleware_api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = api_path_suffix(path, public_base_path) {
        return Some(suffix);
    }

    let base = public_base_path.trim_end_matches('/');
    if !base.is_empty() && base != "/" && path.strip_prefix(base).is_some() {
        return None;
    }

    path.strip_prefix('/').filter(|suffix| !suffix.is_empty())
}

pub async fn auth_middleware(
    State(state): State<Arc<WebState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Only these auth endpoints are reachable without a session. Everything
    // else under auth/ (change-password, user management) requires login.
    const PUBLIC_AUTH_PATHS: &[&str] = &["auth/login", "auth/check", "auth/setup", "auth/logout"];
    let api_suffix = middleware_api_path_suffix(req.uri().path(), &state.public_base_path);
    if api_suffix.is_some_and(|suffix| PUBLIC_AUTH_PATHS.contains(&suffix)) {
        return next.run(req).await;
    }

    // Non-API requests (static files) are always accessible.
    if api_suffix.is_none() {
        return next.run(req).await;
    }

    if state.password_disabled {
        return next.run(req).await;
    }

    if !has_any_account(&state).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Check session token
    let token = extract_session_token(&req);
    if let Some(ref token) = token {
        if state.sessions.read().await.contains_key(token) {
            // 在下游处理器及其 await 到的池创建路径上注入当前登录会话的 owner 作用域，
            // 使 save_password=false 连接的临时密码按会话隔离（见 SessionCredentialStore）。
            let owner = token.clone();
            return dbx_core::session_credentials::with_credential_owner(
                Some(owner),
                async move { next.run(req).await },
            )
            .await;
        }
    }

    StatusCode::UNAUTHORIZED.into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        api_path_suffix, auth_middleware, change_password, check, create_user, delete_user, hash_password, list_users,
        login, middleware_api_path_suffix, setup, CreateUserRequest, LoginRequest, SetupRequest,
    };
    use crate::state::WebState;
    use axum::body::Body;
    use axum::extract::{Path, State};
    use axum::http::{Request, StatusCode};
    use axum::Json;
    use dbx_core::connection::AppState;
    use dbx_core::storage::Storage;
    use std::sync::Arc;

    #[test]
    fn api_path_suffix_handles_root_api_paths() {
        assert_eq!(api_path_suffix("/api/auth/check", "/"), Some("auth/check"));
        assert_eq!(api_path_suffix("/api/query/execute", "/"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/"), None);
    }

    #[test]
    fn api_path_suffix_handles_mounted_api_paths() {
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/dbx"), Some("auth/check"));
        assert_eq!(api_path_suffix("/tools/dbx/api/query/execute", "/tools/dbx"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/login", "/dbx"), None);
    }

    #[test]
    fn middleware_api_path_suffix_handles_nested_router_paths() {
        assert_eq!(middleware_api_path_suffix("/auth/check", "/"), Some("auth/check"));
        assert_eq!(middleware_api_path_suffix("/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/api/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/api/connection/list", "/dbx"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/login", "/dbx"), None);
    }

    async fn test_state() -> (Arc<WebState>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("dbx-web-auth-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = Storage::open(&dir.join("dbx.db")).await.unwrap();
        let app = Arc::new(AppState::new_with_plugin_dir(storage, dir.join("plugins")));
        (Arc::new(WebState::for_tests(app, dir.clone())), dir)
    }

    fn login_body(username: Option<&str>, password: &str) -> Json<LoginRequest> {
        Json(LoginRequest { username: username.map(|u| u.to_string()), password: password.to_string() })
    }

    async fn login_token(state: &Arc<WebState>, username: Option<&str>, password: &str) -> String {
        let res = login(State(state.clone()), login_body(username, password)).await.unwrap();
        let cookie = res
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .expect("login should set a session cookie")
            .to_string();
        cookie.strip_prefix("dbx_session=").unwrap().split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn setup_creates_first_user_and_rejects_second_setup() {
        let (state, dir) = test_state().await;

        // Fresh state reports setup_required.
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = check(State(state.clone()), req).await;
        assert!(res.setup_required);
        assert!(!res.authenticated);

        let res = setup(
            State(state.clone()),
            Json(SetupRequest { username: "admin".to_string(), password: "secret".to_string() }),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(state.app.storage.count_users().await.unwrap(), 1);
        assert!(*state.has_db_users.read().await);

        // Second setup attempt is forbidden.
        let err = setup(
            State(state.clone()),
            Json(SetupRequest { username: "other".to_string(), password: "secret".to_string() }),
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::FORBIDDEN);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn login_with_username_and_password_only_default() {
        let (state, dir) = test_state().await;
        state.app.storage.create_user("admin", &hash_password("secret").unwrap()).await.unwrap();
        state.app.storage.create_user("alice", &hash_password("wonderland").unwrap()).await.unwrap();
        *state.has_db_users.write().await = true;

        // Wrong password is rejected.
        let err = login(State(state.clone()), login_body(Some("alice"), "wrong")).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);

        // Unknown user is rejected.
        let err = login(State(state.clone()), login_body(Some("nobody"), "secret")).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);

        // Password-only login maps to the default "admin" account.
        let token = login_token(&state, None, "secret").await;
        assert_eq!(state.sessions.read().await.get(&token).map(String::as_str), Some("admin"));

        // Named user login works.
        let token = login_token(&state, Some("alice"), "wonderland").await;
        assert_eq!(state.sessions.read().await.get(&token).map(String::as_str), Some("alice"));

        // check reports the session's username.
        let req = Request::builder().header("cookie", format!("dbx_session={token}")).body(Body::empty()).unwrap();
        let res = check(State(state.clone()), req).await;
        assert!(res.authenticated);
        assert_eq!(res.username.as_deref(), Some("alice"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn change_password_updates_db_user() {
        let (state, dir) = test_state().await;
        state.app.storage.create_user("admin", &hash_password("old").unwrap()).await.unwrap();
        *state.has_db_users.write().await = true;
        let token = login_token(&state, None, "old").await;

        let body = serde_json::to_string(&serde_json::json!({"old_password": "old", "new_password": "new"})).unwrap();
        let req = Request::builder().header("cookie", format!("dbx_session={token}")).body(Body::from(body)).unwrap();
        let res = change_password(State(state.clone()), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Old password no longer works, new one does.
        assert!(login(State(state.clone()), login_body(None, "old")).await.is_err());
        login_token(&state, None, "new").await;

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn env_bootstrap_user_login_and_change_password_rejected() {
        let (state, dir) = test_state().await;
        let mut bootstrap = state.bootstrap_users.clone();
        bootstrap.insert("hostadmin".to_string(), hash_password("envpw").unwrap());
        // Rebuild state with bootstrap users (for_tests creates an empty map).
        let state = {
            let mut s = WebState::for_tests(state.app.clone(), dir.clone());
            s.bootstrap_users = bootstrap;
            Arc::new(s)
        };

        let token = login_token(&state, Some("hostadmin"), "envpw").await;
        assert_eq!(state.sessions.read().await.get(&token).map(String::as_str), Some("hostadmin"));

        // Env accounts cannot change their password through the API.
        let body = serde_json::to_string(&serde_json::json!({"old_password": "envpw", "new_password": "new"})).unwrap();
        let req = Request::builder().header("cookie", format!("dbx_session={token}")).body(Body::from(body)).unwrap();
        let res = change_password(State(state.clone()), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn create_and_delete_user_guards() {
        let (state, dir) = test_state().await;
        state.app.storage.create_user("admin", &hash_password("secret").unwrap()).await.unwrap();
        *state.has_db_users.write().await = true;
        let admin_token = login_token(&state, None, "secret").await;

        // Duplicate username is rejected (case-insensitive).
        let res = create_user(
            State(state.clone()),
            Json(CreateUserRequest { username: "ADMIN".to_string(), password: "x".to_string() }),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);

        let res = create_user(
            State(state.clone()),
            Json(CreateUserRequest { username: "bob".to_string(), password: "pw".to_string() }),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let users = state.app.storage.list_users().await.unwrap();
        let admin_id = users.iter().find(|u| u.username == "admin").unwrap().id;
        let bob_id = users.iter().find(|u| u.username == "bob").unwrap().id;

        // Deleting your own account is refused.
        let req =
            Request::builder().header("cookie", format!("dbx_session={admin_token}")).body(Body::empty()).unwrap();
        let res = delete_user(State(state.clone()), Path(admin_id), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Deleting another user works and drops their sessions.
        let bob_token = login_token(&state, Some("bob"), "pw").await;
        let req =
            Request::builder().header("cookie", format!("dbx_session={admin_token}")).body(Body::empty()).unwrap();
        let res = delete_user(State(state.clone()), Path(bob_id), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!state.sessions.read().await.contains_key(&bob_token));

        // Deleting the last remaining user is refused.
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = delete_user(State(state.clone()), Path(admin_id), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.app.storage.count_users().await.unwrap(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn middleware_protects_user_management_but_not_login() {
        use axum::routing::{get, post};
        use tower::ServiceExt;

        let (state, dir) = test_state().await;
        state.app.storage.create_user("admin", &hash_password("secret").unwrap()).await.unwrap();
        *state.has_db_users.write().await = true;

        let app = axum::Router::new()
            .route("/api/auth/users", get(list_users))
            .route("/api/auth/login", post(login))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state.clone());

        // User management requires a session.
        let res =
            app.clone().oneshot(Request::builder().uri("/api/auth/users").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // Login stays reachable without a session.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"secret"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let cookie = res.headers().get("set-cookie").unwrap().to_str().unwrap().to_string();
        let token = cookie.strip_prefix("dbx_session=").unwrap().split(';').next().unwrap();

        // With a session, user management is allowed.
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/auth/users")
                    .header("cookie", format!("dbx_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        std::fs::remove_dir_all(&dir).ok();
    }
}
