//! Authentication module for Seance API
//!
//! Provides JWT-based authentication with configurable user credentials.
//! By default, uses a single admin user with credentials from environment variables.

use axum::{
    extract::{Extension, FromRequestParts, Request, State},
    http::{header::AUTHORIZATION, request::Parts, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use seance_db::SqliteConnection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use utoipa::ToSchema;

/// JWT token expiration time in seconds (24 hours)
const TOKEN_EXPIRATION_SECS: u64 = 24 * 60 * 60;

/// Cookie name for storing JWT token
pub const AUTH_COOKIE_NAME: &str = "seance_auth";

/// Authenticated username, inserted into request extensions by
/// `auth_middleware` so handlers can attribute audit-log entries to the real
/// user. When authentication is disabled the username is `"local"`.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub String);

/// Authenticated user's role (`admin` or `examiner`), taken from the JWT and
/// inserted into request extensions alongside `AuthenticatedUser`. Drives the
/// `AdminUser` role guard. When authentication is disabled the role is
/// `"admin"` so admin-only endpoints remain reachable in local/dev mode.
#[derive(Debug, Clone)]
pub struct AuthenticatedRole(pub String);

/// The token a request was authenticated with: its `jti` and `iat`.
///
/// Inserted beside [`AuthenticatedUser`] so a handler that OUTLIVES the request
/// — the SSE `/events` stream — can re-run the middleware's liveness check on a
/// timer. The middleware checks revocation, `active` and the two invalidation
/// stamps once, at connect; a stream that then ran for hours kept delivering
/// artifact and ingest events to a session that had logged out or been
/// deactivated, because nothing on the stream could ask again without the
/// token's identity. Absent when authentication is disabled: there is no token
/// to revoke, and a handler treats that as "nothing to re-check".
#[derive(Debug, Clone)]
pub struct AuthenticatedToken {
    pub jti: String,
    pub iat: u64,
}

/// Extractor that admits only admins. Reads the role placed in request
/// extensions by `auth_middleware`; anything other than `admin` is rejected
/// with 403. The wrapped value is the admin's username for audit attribution.
///
/// Placement: handlers guarded by this MUST sit behind `auth_middleware`
/// (i.e. on the protected router), otherwise the extensions are absent and the
/// request is rejected.
pub struct AdminUser(pub String);

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let role = parts
            .extensions
            .get::<AuthenticatedRole>()
            .map(|r| r.0.clone());
        let user = parts
            .extensions
            .get::<AuthenticatedUser>()
            .map(|u| u.0.clone());
        match (user, role) {
            (Some(username), Some(role)) if role == "admin" => Ok(AdminUser(username)),
            _ => Err((
                StatusCode::FORBIDDEN,
                Json(AuthErrorResponse {
                    error: AuthErrorData {
                        code: "FORBIDDEN".to_string(),
                        message: "Admin privileges required".to_string(),
                    },
                }),
            )
                .into_response()),
        }
    }
}

/// Hash a plaintext password with bcrypt at the default cost. Hashing lives in
/// the API layer (never the DB layer), matching how `AuthConfig` hashes the
/// admin password.
pub fn hash_password(password: &str) -> Result<String, String> {
    hash(password, DEFAULT_COST).map_err(|e| format!("Failed to hash password: {}", e))
}

/// Enforce per-case access for a request. This is the single choke point for
/// case-scoped authorization; call it at the top of any handler that must be
/// restricted to users granted access to `case_id`.
///
/// Rules:
/// - Admins (role == "admin") ALWAYS pass. This also covers local/dev mode,
///   where `auth_middleware` attributes requests to the `admin`-roled `local`
///   identity, so disabling auth does not break case access.
/// - Any other role is resolved to a user id by username and checked against
///   the `case_access` table via `user_can_access_case`.
///
/// Fail-closed semantics: an unknown/unresolvable username (deleted account or
/// a token subject with no user row) is denied with 403, never allowed. A DB
/// error surfaces as 500 (the request fails) rather than silently permitting.
pub async fn require_case_access(
    state: &crate::AppState,
    username: &str,
    role: &str,
    case_id: uuid::Uuid,
) -> Result<(), crate::ApiError> {
    if role == "admin" {
        return Ok(());
    }

    let user = state.db.get_user_by_username(username).await.map_err(|e| {
        crate::ApiError::InternalServerError(format!("Failed to resolve user: {}", e))
    })?;

    let Some(user) = user else {
        // Authenticated token subject that maps to no user row: deny.
        return Err(crate::ApiError::Forbidden(
            "You do not have access to this case".to_string(),
        ));
    };

    let allowed = state
        .db
        .user_can_access_case(user.id, case_id)
        .await
        .map_err(|e| {
            crate::ApiError::InternalServerError(format!("Failed to check case access: {}", e))
        })?;

    if allowed {
        Ok(())
    } else {
        Err(crate::ApiError::Forbidden(
            "You do not have access to this case".to_string(),
        ))
    }
}

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Claims {
    /// Subject (username)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// User role
    pub role: String,
    /// When true, the session may only change the password (forced rotation of
    /// a default-seeded credential). `serde(default)` so pre-existing tokens
    /// decode as `false`.
    #[serde(default)]
    pub must_change: bool,
    /// Token id (a UUID). Logout records it in `revoked_tokens` and the auth
    /// middleware refuses a token whose id is on that list (SEC-001).
    /// `serde(default)` so a token minted before the claim existed still
    /// decodes -- and is then refused, because a session that cannot be
    /// logged out is not accepted.
    #[serde(default)]
    pub jti: String,
}

/// Login request payload
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response payload
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: u64,
    pub username: String,
    pub role: String,
    /// When true, the client must immediately change the password; the issued
    /// token is scoped to the password-change endpoint until it does.
    #[serde(default)]
    pub must_change_password: bool,
    /// The authenticated user's id, so the client can target the
    /// `/users/{id}/password` endpoint (e.g. for a forced change). None for the
    /// empty-table bootstrap fallback, which never requires a change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<uuid::Uuid>,
}

/// Auth error response
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthErrorResponse {
    pub error: AuthErrorData,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthErrorData {
    pub code: String,
    pub message: String,
}

/// Whether an operator-supplied `SEANCE_ADMIN_PASSWORD` may be pinned as the
/// initial admin credential.
///
/// This env var is the one route into the `users` table that never passes
/// `validate_new_password`, and `bootstrap_admin` reads a non-empty hash as
/// "the operator chose this" and seeds the account with `must_change = false`.
/// An empty value still hashes to a perfectly valid bcrypt digest of the empty
/// string, so the admin stayed reachable with no password at all, indefinitely
/// (HUNT-003). Anything the password-change endpoint would refuse is refused
/// here too; the bootstrap then falls back to its forced-change default, which
/// the operator is told about at startup.
fn env_admin_password_is_acceptable(password: &str) -> bool {
    !password.trim().is_empty() && password.len() >= crate::MIN_PASSWORD_LEN
}

/// Authentication configuration
#[derive(Clone)]
pub struct AuthConfig {
    /// JWT secret key for signing tokens
    pub jwt_secret: String,
    /// Admin username (from environment)
    pub admin_username: String,
    /// Admin password hash (bcrypt)
    pub admin_password_hash: String,
    /// Whether authentication is enabled
    pub enabled: bool,
}

impl AuthConfig {
    /// Create AuthConfig from environment variables
    ///
    /// Environment variables:
    /// - `SEANCE_AUTH_ENABLED`: Set to "false" to disable authentication (default: true)
    /// - `SEANCE_JWT_SECRET`: Secret key for JWT signing. When unset **or empty**,
    ///   a cryptographically random secret is generated for this process, so
    ///   tokens do not survive a restart.
    /// - `SEANCE_ADMIN_USERNAME`: Admin username (default: "admin")
    /// - `SEANCE_ADMIN_PASSWORD`: Admin password. When unset, or too weak to pin
    ///   (see [`env_admin_password_is_acceptable`]), a random password is
    ///   generated and logged once (no hardcoded default).
    pub fn from_env() -> Self {
        let enabled = std::env::var("SEANCE_AUTH_ENABLED")
            .map(|v| v.to_lowercase() != "false")
            .unwrap_or(true);

        let jwt_secret = match std::env::var("SEANCE_JWT_SECRET") {
            Ok(secret) if !secret.trim().is_empty() => secret,
            // An empty (or whitespace-only) value is not a configured secret.
            // It used to be taken verbatim as the HS256 key, and a key that is
            // guessed in one attempt lets anyone mint a token with role=admin,
            // so it is treated exactly like an unset variable (HUNT-002).
            Ok(_) => {
                if enabled {
                    warn!(
                        "SEANCE_JWT_SECRET is set but empty. An empty HMAC key can be guessed by \
                         anyone, so it is ignored and a random secret was generated for this run. \
                         Set SEANCE_JWT_SECRET to a high-entropy value."
                    );
                }
                Self::generate_random_secret()
            }
            Err(_) => {
                if enabled {
                    info!(
                        "SEANCE_JWT_SECRET not set; generated a random secret for this run. \
                         Existing sessions will not survive a server restart. \
                         Set SEANCE_JWT_SECRET to keep tokens valid across restarts."
                    );
                }
                // Two UUIDv4s = 64 hex chars backed by ~244 bits of CSPRNG
                // entropy (uuid v4 uses the OS RNG). A per-process random
                // secret is strictly safer than any hardcoded default, which
                // would let anyone forge admin tokens.
                Self::generate_random_secret()
            }
        };

        let admin_username =
            std::env::var("SEANCE_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());

        // The admin password hash is populated ONLY when the operator pins
        // SEANCE_ADMIN_PASSWORD to a password this product would itself accept.
        // When unset (or refused) it is left empty: `bootstrap_admin` then seeds
        // the initial admin with the loopback default ('seance', forced-change)
        // or a generated password (exposed bind). This avoids the old bug where
        // a fresh random password was regenerated and logged on every restart
        // but never matched the already-seeded admin row.
        let admin_password_hash = match std::env::var("SEANCE_ADMIN_PASSWORD") {
            Ok(p) if env_admin_password_is_acceptable(&p) => {
                hash(&p, DEFAULT_COST).expect("Failed to hash admin password")
            }
            Ok(_) => {
                warn!(
                    "SEANCE_ADMIN_PASSWORD is set but is empty or shorter than the {}-character \
                     minimum this server enforces everywhere else, so it is NOT being used. The \
                     initial admin will be seeded with a forced-change credential instead.",
                    crate::MIN_PASSWORD_LEN
                );
                String::new()
            }
            Err(_) => String::new(),
        };

        Self {
            jwt_secret,
            admin_username,
            admin_password_hash,
            enabled,
        }
    }

    /// Generate a cryptographically random JWT secret (64 hex chars).
    fn generate_random_secret() -> String {
        format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        )
    }

    /// Validate username and password
    pub fn validate_credentials(&self, username: &str, password: &str) -> bool {
        if username != self.admin_username {
            return false;
        }
        verify(password, &self.admin_password_hash).unwrap_or(false)
    }

    /// Generate JWT token for a user
    pub fn generate_token(&self, username: &str, role: &str) -> Result<(String, u64), String> {
        self.generate_token_full(username, role, false)
    }

    /// Like [`generate_token`] but marks the token as password-change-only when
    /// `must_change` is set (the forced-rotation flow for a default credential).
    pub fn generate_token_full(
        &self,
        username: &str,
        role: &str,
        must_change: bool,
    ) -> Result<(String, u64), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_secs();

        let exp = now + TOKEN_EXPIRATION_SECS;

        let claims = Claims {
            sub: username.to_string(),
            exp,
            iat: now,
            role: role.to_string(),
            must_change,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|e| format!("Token generation failed: {}", e))?;

        Ok((token, exp))
    }

    /// Validate JWT token and extract claims.
    ///
    /// `leeway` is set to zero rather than left at `Validation::default()`'s
    /// **60 seconds**. The default accepts a token for a minute past its `exp`,
    /// and the revoked-token sweep deletes a row once `expires_at < now` — so a
    /// logged-out token whose row had just been swept would pass signature and
    /// expiry checks, find no revocation row, and be accepted, for up to a
    /// minute after it expired (SEC-001's window). An expired token is expired:
    /// on a forensic workstation there is no clock skew worth trading a live
    /// credential for, and the sweep additionally keeps a margin so the two
    /// cannot open the window between them again.
    pub fn validate_token(&self, token: &str) -> Result<Claims, String> {
        let mut validation = Validation::default();
        validation.leeway = 0;
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|e| format!("Token validation failed: {}", e))
    }
}

/// Whether auth cookies should carry the `Secure` attribute, driven by the
/// `SEANCE_COOKIE_SECURE` env var ("1"/"true"/"yes", case-insensitive).
///
/// Defaults to false: Seance normally serves plain HTTP on 127.0.0.1, and a
/// Secure cookie would not be sent by browsers over http:// from non-localhost
/// hosts. Set SEANCE_COOKIE_SECURE=true whenever the API is served over HTTPS.
fn cookie_secure_from_env() -> bool {
    std::env::var("SEANCE_COOKIE_SECURE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Validate credentials against the `users` table and return the real
/// `(username, role)` on success.
///
/// Order of checks:
/// 1. Look the username up in the DB. If found: reject if deactivated, then
///    verify the bcrypt hash. The stored `role` (admin/examiner) is returned so
///    the token carries the real role.
/// 2. If the username is not in the DB, fall back to the env-configured admin
///    ONLY while the table is still empty (bootstrap race, before the initial
///    admin row is seeded). Once any user exists, the env admin is inert.
///
/// Returns `None` for any failure (unknown user, wrong password, deactivated,
/// or a DB error), so the caller emits an indistinguishable 401.
async fn authenticate_user(
    db: &SqliteConnection,
    auth_config: &AuthConfig,
    username: &str,
    password: &str,
) -> Option<(String, String, bool)> {
    match db.get_user_by_username(username).await {
        Ok(Some(user)) => {
            if !user.active {
                debug!("Login rejected: user '{}' is deactivated", username);
                return None;
            }
            if verify(password, &user.password_hash).unwrap_or(false) {
                Some((user.username, user.role, user.must_change_password))
            } else {
                None
            }
        }
        Ok(None) => {
            // Bootstrap fallback: only while no users exist yet.
            match db.count_users().await {
                Ok(0) if auth_config.validate_credentials(username, password) => Some((
                    auth_config.admin_username.clone(),
                    "admin".to_string(),
                    false,
                )),
                _ => None,
            }
        }
        Err(e) => {
            warn!("User lookup failed during login: {}", e);
            None
        }
    }
}

/// Login handler
pub async fn login(
    State(auth_config): State<AuthConfig>,
    State(login_limiter): State<LoginRateLimiter>,
    State(db): State<Arc<SqliteConnection>>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    // Rate limit per username (plus a global backstop) BEFORE the expensive
    // bcrypt verify, so brute-force attempts are throttled cheaply.
    if !login_limiter.try_acquire(&request.username) {
        warn!(
            "Login rate limit exceeded for username '{}'",
            request.username
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            jar,
            Json(AuthErrorResponse {
                error: AuthErrorData {
                    code: "RATE_LIMIT_EXCEEDED".to_string(),
                    message: "Too many login attempts. Please try again later.".to_string(),
                },
            }),
        )
            .into_response();
    }

    // Validate credentials against the users table (with env-admin bootstrap
    // fallback while the table is empty). The role comes from the DB.
    let (username, role, must_change) =
        match authenticate_user(&db, &auth_config, &request.username, &request.password).await {
            Some(triple) => triple,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    jar,
                    Json(AuthErrorResponse {
                        error: AuthErrorData {
                            code: "INVALID_CREDENTIALS".to_string(),
                            message: "Invalid username or password".to_string(),
                        },
                    }),
                )
                    .into_response();
            }
        };

    match auth_config.generate_token_full(&username, &role, must_change) {
        Ok((token, expires_at)) => {
            // Set cookie
            let cookie = Cookie::build((AUTH_COOKIE_NAME, token.clone()))
                .path("/")
                .http_only(true)
                .secure(cookie_secure_from_env())
                // Match the CSRF cookie's SameSite=Strict so the session cookie
                // is not attached to cross-site requests (defense in depth).
                .same_site(SameSite::Strict)
                .max_age(time::Duration::seconds(TOKEN_EXPIRATION_SECS as i64))
                .build();

            let updated_jar = jar.add(cookie);

            // Resolve the user's id so the client can target /users/{id}/password
            // (needed for the forced-change flow).
            let user_id = db
                .get_user_by_username(&username)
                .await
                .ok()
                .flatten()
                .map(|u| u.id);

            (
                StatusCode::OK,
                updated_jar,
                Json(LoginResponse {
                    token,
                    expires_at,
                    username,
                    role,
                    must_change_password: must_change,
                    user_id,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            jar,
            Json(AuthErrorResponse {
                error: AuthErrorData {
                    code: "TOKEN_GENERATION_FAILED".to_string(),
                    message: e,
                },
            }),
        )
            .into_response(),
    }
}

/// Logout handler: revokes the session's token and clears the auth cookie.
///
/// Clearing the cookie alone left a captured Bearer token valid for the rest
/// of its 24 h, so an action taken after the logout would have been attributed
/// to an examiner who had ended their session (SEC-001). The token's `jti` is
/// written to `revoked_tokens` -- the durable record, so a restart cannot
/// resurrect it -- and the middleware refuses it from then on. A request with
/// no token, or an invalid one, still clears the cookie and answers 200: there
/// is nothing to revoke, and the client's intent is the same.
pub async fn logout(
    State(auth_config): State<AuthConfig>,
    State(db): State<Arc<SqliteConnection>>,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
) -> Response {
    // Whether the token outlives this sign-out. The cookie is cleared either
    // way; this is about the credential, which the caller has to be told about.
    let mut revocation_failed = false;

    if let Some(claims) = extract_token(&headers, &jar)
        .and_then(|t| auth_config.validate_token(&t).ok())
        .filter(|c| !c.jti.is_empty())
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let user_id = db
            .get_user_by_username(&claims.sub)
            .await
            .ok()
            .flatten()
            .map(|u| u.id);
        match db
            .revoke_token(&claims.jti, user_id, &claims.sub, claims.exp as i64, now)
            .await
        {
            Ok(()) => {
                info!(
                    "Session {} for '{}' logged out and revoked",
                    claims.jti, claims.sub
                );
                // Ending a session is a custody event, the same as starting
                // one: the audit log must be able to say that nothing after
                // this point was done under this session. Best effort, and
                // once per logout — a dead token replayed afterwards is
                // rejected without touching the chain.
                if let Err(e) = db
                    .record_audit_event(
                        None,
                        &claims.sub,
                        "session_logout",
                        Some("session"),
                        None,
                        Some(&format!("jti {} revoked", claims.jti)),
                    )
                    .await
                {
                    warn!("Logout for '{}' could not be audited: {}", claims.sub, e);
                }
            }
            Err(e) => {
                // The cookie is still cleared, but the token is now a live
                // credential the server cannot refuse.
                //
                // This used to `warn!` and fall through to
                // `200 {"message":"Logged out successfully"}`. A server-side log
                // line is not "saying so loudly" to the person signing out: the
                // examiner was shown as signed out while their Bearer token
                // stayed valid for the rest of its 24 hours — the attribution
                // gap `SEC-001` was opened to close, reappearing in the failure
                // path of its own fix.
                warn!(
                    "Logout for '{}' could not record token revocation: {}",
                    claims.sub, e
                );
                revocation_failed = true;
            }
        }
        // Rows for tokens that have expired on their own guard nothing; one
        // bounded sweep per logout keeps the table the size of the live
        // session count.
        if let Err(e) = db.purge_expired_revoked_tokens(now).await {
            debug!("Revoked-token purge failed: {}", e);
        }
    }

    // Clear the auth cookie with the SAME attributes login set (HttpOnly,
    // SameSite=Strict, and Secure when configured). A removal that omits these
    // may not match the browser's stored Secure cookie, leaving the session
    // cookie in place after a logout that appears to succeed (BUG-077).
    let cookie = Cookie::build((AUTH_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(cookie_secure_from_env())
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(0))
        .build();

    let updated_jar = jar.remove(cookie);

    if revocation_failed {
        // The cookie is gone, so this browser is signed out; the TOKEN is not,
        // and only the caller can act on that. Named as the specific thing it
        // is — a session that outlives the sign-out — rather than a generic
        // failure, because what an examiner does about it (treat the session as
        // live until it expires, and say so if actions appear under their name)
        // depends on knowing which.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            updated_jar,
            Json(serde_json::json!({
                "error": "REVOCATION_FAILED",
                "message": "You are signed out of this browser, but the server could not revoke \
                            the session token. It stays valid until it expires, so treat this \
                            session as live and tell an administrator.",
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        updated_jar,
        Json(serde_json::json!({ "message": "Logged out successfully" })),
    )
        .into_response()
}

/// Extract a JWT from the `Authorization: Bearer` header, falling back to the
/// auth cookie. Shared by `auth_middleware` and `get_current_user` so both
/// accept the same credential forms in the same order.
fn extract_token(headers: &axum::http::HeaderMap, jar: &CookieJar) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(String::from)
        .or_else(|| jar.get(AUTH_COOKIE_NAME).map(|c| c.value().to_string()))
}

/// Get current user info from token (Authorization header or cookie).
///
/// Re-validates the account against the users table exactly as
/// [`auth_middleware`] does, and answers with the DB role rather than the
/// token's. Without that, a deactivated or demoted examiner kept seeing an
/// authenticated admin session in the UI — while every protected endpoint
/// correctly refused them — for as long as the JWT lived. Session chrome that
/// contradicts the API is how an examiner misses that they have been locked
/// out mid-case.
pub async fn get_current_user(
    State(auth_config): State<AuthConfig>,
    State(db): State<Arc<SqliteConnection>>,
    jar: CookieJar,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let unauthenticated = || {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "authenticated": false })),
        )
            .into_response()
    };

    let Some(token) = extract_token(&headers, &jar) else {
        return unauthenticated();
    };
    let Ok(claims) = auth_config.validate_token(&token) else {
        return unauthenticated();
    };
    // A logged-out session is not a session (SEC-001). A revocation lookup that
    // ERRORS must not be read as "not revoked": `auth_middleware` fails closed on
    // the same error, so collapsing it here would have this endpoint report a
    // live session for a token every protected route refuses — the disagreement
    // this handler exists to prevent. Unknown means unauthenticated.
    if claims.jti.is_empty() {
        return unauthenticated();
    }
    match db.is_token_revoked(&claims.jti).await {
        Ok(false) => {}
        Ok(true) => return unauthenticated(),
        Err(e) => {
            warn!("/auth/me could not check token revocation: {}", e);
            return unauthenticated();
        }
    }

    // Same rules as the middleware: the account must still exist and be active,
    // and the token must post-date the last password change. The env-admin
    // bootstrap (no row, empty users table) is the one identity with no row.
    let (role, must_change) = match db.get_user_by_username(&claims.sub).await {
        Ok(Some(u)) => {
            if !u.active {
                return unauthenticated();
            }
            if u.password_changed_at > 0 && claims.iat <= u.password_changed_at as u64 {
                return unauthenticated();
            }
            // And a token from before the account was last deactivated is not a
            // session, whether or not the account has since been reactivated
            // (SEC-002). Same rule as the middleware, for the same reason the
            // revocation check above is duplicated here: this endpoint must not
            // report a live session for a token every protected route refuses.
            if u.sessions_invalid_before > 0 && claims.iat <= u.sessions_invalid_before as u64 {
                return unauthenticated();
            }
            (u.role, u.must_change_password)
        }
        Ok(None) => {
            let bootstrap =
                claims.sub == auth_config.admin_username && matches!(db.count_users().await, Ok(0));
            if !bootstrap {
                return unauthenticated();
            }
            (claims.role.clone(), false)
        }
        Err(e) => {
            // Could not check: say so rather than assert a session is valid.
            warn!("/auth/me revalidation DB error for '{}': {}", claims.sub, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthErrorResponse {
                    error: AuthErrorData {
                        code: "AUTH_BACKEND_ERROR".to_string(),
                        message: "Could not verify the session.".to_string(),
                    },
                }),
            )
                .into_response();
        }
    };

    // The chosen skin travels with the identity rather than on a second
    // request, so the app learns who it is and how they want to see it in one
    // answer. A separate fetch would paint the default palette first and swap it
    // a moment later, which is a flash on every cold load.
    //
    // A read that fails is `null` — "no stored choice" — not a 500: a database
    // hiccup must not lock an examiner out of the product over a colour scheme.
    // The client falls back to the default, which is what it does for a user who
    // never chose, and the next load asks again.
    let theme = match db.get_user_theme(&claims.sub).await {
        Ok(theme) => theme,
        Err(e) => {
            warn!(
                "/auth/me could not read the theme for '{}': {}",
                claims.sub, e
            );
            None
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "authenticated": true,
            "username": claims.sub,
            "role": role,
            "must_change_password": must_change,
            "expires_at": claims.exp,
            "theme": theme
        })),
    )
        .into_response()
}

/// `PUT /api/v1/auth/theme` — remember this user's chosen skin.
///
/// Registered among the **protected** routes rather than in [`auth_router`].
/// That router is the unauthenticated surface — login, logout, and the `me`
/// probe that answers for a token the caller may not have — and it validates
/// tokens itself. Changing a stored preference is an authenticated action, so
/// it sits behind the middleware that populates [`AuthenticatedUser`] and reads
/// the identity from there rather than re-implementing the check.
///
/// The body is `{"theme": "<skin>:<mode>"}`, or `{"theme": null}` to go back to
/// following the build's default. The value is validated for shape by
/// `seance_db::set_user_theme` and stored against the calling user — never
/// against a user named in the request, so this endpoint cannot be used to
/// change anyone else's anything.
///
/// The env-admin bootstrap identity has no row in `users`, so it has nowhere to
/// store a preference; it is told so plainly rather than silently succeeding and
/// forgetting.
pub async fn set_theme(
    Extension(AuthenticatedUser(username)): Extension<AuthenticatedUser>,
    State(state): State<crate::AppState>,
    Json(body): Json<ThemeRequest>,
) -> Response {
    // The row is looked up from the AUTHENTICATED name, never from anything in
    // the request body, so this endpoint can only ever change the caller's own
    // preference.
    let id = match state.db.get_user_by_username(&username).await {
        Ok(Some(row)) => row.id,
        Ok(None) => {
            // The env-admin bootstrap has no row, so it has nowhere to store a
            // preference. Said plainly rather than silently succeeding and
            // forgetting, which would look like the product losing the setting.
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "NO_USER_RECORD",
                    "message": "This session is the bootstrap administrator, which has no user \
                                row to remember a theme against. Create a named account and sign \
                                in as it to keep a theme.",
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(
                "theme: could not load the user row for '{}': {}",
                username,
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "LOOKUP_FAILED",
                    "message": "Could not read this account.",
                })),
            )
                .into_response();
        }
    };

    match state.db.set_user_theme(id, body.theme.as_deref()).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "theme": body.theme })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "NO_SUCH_USER",
                "message": "This account no longer exists.",
            })),
        )
            .into_response(),
        // A rejected VALUE and a failed WRITE are different answers, and
        // collapsing them told a client its perfectly good "nature:light" was
        // malformed whenever the database was locked — so it would retry
        // forever, correcting something that was never wrong. The validator is
        // asked first, so which of the two happened is known rather than
        // guessed from an error string.
        Err(e) if !seance_db::is_valid_theme_value(body.theme.as_deref()) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "INVALID_THEME",
                "message": e.to_string(),
            })),
        )
            .into_response(),
        Err(e) => {
            // The detail goes to the log, not to the browser: an anyhow chain
            // from sqlx names the schema and the file path.
            tracing::error!("theme: could not store the theme for '{}': {}", username, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "THEME_NOT_STORED",
                    "message": "The theme is applied but could not be saved. It will not be \
                                remembered for the next session.",
                })),
            )
                .into_response()
        }
    }
}

/// The body of a theme change. `null` clears the stored choice.
#[derive(serde::Deserialize)]
pub struct ThemeRequest {
    pub theme: Option<String>,
}

/// Is this session still one the server would accept a request from?
///
/// The four refusals `auth_middleware` applies after the signature check — the
/// token revoked, the account gone or inactive, a password change since the
/// token was minted, a deactivation since it was minted — as one question, so
/// the SSE stream can ask it on its tick and give the same answer a REST call
/// would get at that moment. Fails closed: a lookup the database cannot answer
/// is `false`, exactly as the middleware treats it.
pub async fn session_still_live(
    db: &SqliteConnection,
    username: &str,
    token: &AuthenticatedToken,
) -> bool {
    if token.jti.is_empty() {
        return false;
    }
    match db.is_token_revoked(&token.jti).await {
        Ok(false) => {}
        Ok(true) | Err(_) => return false,
    }
    match db.get_user_by_username(username).await {
        Ok(Some(u)) => {
            u.active
                && !(u.password_changed_at > 0 && token.iat <= u.password_changed_at as u64)
                && !(u.sessions_invalid_before > 0 && token.iat <= u.sessions_invalid_before as u64)
        }
        // The env-admin bootstrap has no row and is live while the table is
        // empty, as in the middleware; a deleted user is not.
        Ok(None) => matches!(db.count_users().await, Ok(0)),
        Err(_) => false,
    }
}

/// State for [`auth_middleware`]: the JWT config plus a DB handle so every
/// request can re-check the account against the users table (BUG-004).
#[derive(Clone)]
pub struct AuthLayerState {
    pub config: AuthConfig,
    pub db: Arc<SqliteConnection>,
}

/// Build a 401 JSON response with the given machine code and human message.
fn unauthorized_response(code: &str, message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthErrorResponse {
            error: AuthErrorData {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

/// Whether `claims` names a session that may no longer be used: one that has
/// been logged out, or one minted before tokens carried a `jti` and so can
/// never be logged out. `Err` means the list could not be consulted.
async fn revoked_session(db: &SqliteConnection, claims: &Claims) -> Result<bool, anyhow::Error> {
    if claims.jti.is_empty() {
        return Ok(true);
    }
    db.is_token_revoked(&claims.jti).await
}

/// Authentication middleware
///
/// Validates JWT token from either Authorization header or cookie, then
/// re-validates the account against the DB so deactivation and role changes
/// take effect immediately rather than at token expiry.
/// If authentication is disabled, allows all requests.
pub async fn auth_middleware(
    State(auth): State<AuthLayerState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_config = &auth.config;
    // If auth is disabled, allow all requests attributed to the local user.
    // The local identity is treated as admin so admin-only endpoints stay
    // reachable in local/dev mode.
    if !auth_config.enabled {
        request
            .extensions_mut()
            .insert(AuthenticatedUser("local".to_string()));
        request
            .extensions_mut()
            .insert(AuthenticatedRole("admin".to_string()));
        return next.run(request).await;
    }

    // Authorization header first, then cookie
    let token = extract_token(request.headers(), &jar);

    match token {
        Some(t) => match auth_config.validate_token(&t) {
            Ok(claims) => {
                // A token that has been logged out is refused for the rest of
                // its life (SEC-001). One primary-key lookup, alongside the
                // per-request users lookup below. Logged at debug only: an
                // audit entry per rejected request would let whoever holds a
                // dead token flood the chain of custody.
                match revoked_session(&auth.db, &claims).await {
                    Ok(false) => {}
                    Ok(true) => {
                        debug!(
                            "Rejecting revoked token {} for '{}'",
                            claims.jti, claims.sub
                        );
                        return unauthorized_response(
                            "SESSION_REVOKED",
                            "This session has been logged out; please sign in again.",
                        );
                    }
                    Err(e) => {
                        warn!("Auth revocation check DB error for '{}': {}", claims.sub, e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(AuthErrorResponse {
                                error: AuthErrorData {
                                    code: "AUTH_BACKEND_ERROR".to_string(),
                                    message: "Could not verify the session.".to_string(),
                                },
                            }),
                        )
                            .into_response();
                    }
                }
                // Re-validate the account against the DB so a deactivated user
                // or a demoted admin loses access immediately, not up to 24h
                // later when the JWT expires (BUG-004). `effective_role`,
                // `self_id`, and `db_must_change` come from the DB row, never the
                // (possibly stale) token, except for the env-admin bootstrap
                // which has no row.
                let (effective_role, self_id, db_must_change) =
                    match auth.db.get_user_by_username(&claims.sub).await {
                        Ok(Some(u)) => {
                            // The account still exists: a deactivation takes hold
                            // immediately, and the DB role (not the token's) wins
                            // so a demotion is not carried by a stale token.
                            if !u.active {
                                debug!("Rejecting token for deactivated user '{}'", claims.sub);
                                return unauthorized_response(
                                    "ACCOUNT_INACTIVE",
                                    "This account is no longer active.",
                                );
                            }
                            // A token minted BEFORE the last password change is
                            // rejected so a stolen/leaked session dies on
                            // credential rotation (BUG-076). password_changed_at
                            // == 0 means "never changed since the column existed"
                            // -> nothing to invalidate.
                            //
                            // Both stamps are whole Unix seconds, so a token minted
                            // in the SAME second as the change is indistinguishable
                            // from one minted just before it. Reject that second too
                            // (`<=`): a session that survives a rotation is a
                            // security failure, while a login racing the change by
                            // under a second simply signs in again (BUG-249).
                            if u.password_changed_at > 0
                                && claims.iat <= u.password_changed_at as u64
                            {
                                debug!(
                                "Rejecting token for '{}' issued before its last password change",
                                claims.sub
                            );
                                return unauthorized_response(
                                    "SESSION_SUPERSEDED",
                                    "Your password has changed; please sign in again.",
                                );
                            }
                            // A token minted BEFORE the account was last
                            // deactivated is not a session either (SEC-002).
                            // The `!u.active` refusal above holds only while the
                            // account stays deactivated; reactivating it used to
                            // bring every such token back to life, so a session
                            // nobody re-authenticated resumed attributing work to
                            // an examiner. The stamp is never cleared, so the
                            // refusal outlives the reactivation.
                            //
                            // `<=` for the same whole-second reason as above: a
                            // token minted in the same second as the
                            // deactivation cannot be told from one minted just
                            // before it, and a live session surviving a
                            // deactivation is the failure being closed.
                            if u.sessions_invalid_before > 0
                                && claims.iat <= u.sessions_invalid_before as u64
                            {
                                debug!(
                                    "Rejecting token for '{}' issued before its last deactivation",
                                    claims.sub
                                );
                                return unauthorized_response(
                                    "SESSION_SUPERSEDED",
                                    "This account was deactivated; please sign in again.",
                                );
                            }
                            (u.role, Some(u.id), u.must_change_password)
                        }
                        Ok(None) => {
                            // No row: allow ONLY the env-admin bootstrap, and
                            // only while the users table is still empty. A
                            // DELETED user's signed token must stop working
                            // immediately -- otherwise a deleted admin keeps
                            // full admin (AdminUser / require_case_access
                            // short-circuit on role == "admin") until the JWT
                            // expires up to 24h later (BUG-044).
                            let bootstrap = claims.sub == auth_config.admin_username
                                && matches!(auth.db.count_users().await, Ok(0));
                            if !bootstrap {
                                debug!("Rejecting token for unknown/deleted user '{}'", claims.sub);
                                return unauthorized_response(
                                    "ACCOUNT_INACTIVE",
                                    "This account is no longer active.",
                                );
                            }
                            // Bootstrap env-admin has no row and no self id.
                            (claims.role.clone(), None, false)
                        }
                        Err(e) => {
                            warn!("Auth revalidation DB error for '{}': {}", claims.sub, e);
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(AuthErrorResponse {
                                    error: AuthErrorData {
                                        code: "AUTH_BACKEND_ERROR".to_string(),
                                        message: "Could not verify the session.".to_string(),
                                    },
                                }),
                            )
                                .into_response();
                        }
                    };

                // Forced password rotation: a must-change token may reach only
                // the caller's OWN password-change endpoint and the auth routes.
                // Everything else is 403 until the default credential is rotated.
                // The live DB flag is OR-ed with the token claim so an admin
                // forcing a change takes effect on already-issued sessions
                // immediately, not just at token expiry (BUG-124).
                if claims.must_change || db_must_change {
                    let path = request.uri().path();
                    let own_password = self_id
                        .map(|id| format!("/api/v1/users/{}/password", id))
                        .unwrap_or_default();
                    let allowed = (!own_password.is_empty() && path == own_password)
                        || path.starts_with("/api/v1/auth/");
                    if !allowed {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(AuthErrorResponse {
                                error: AuthErrorData {
                                    code: "PASSWORD_CHANGE_REQUIRED".to_string(),
                                    message: "You must change your password before continuing."
                                        .to_string(),
                                },
                            }),
                        )
                            .into_response();
                    }
                }
                debug!("Authenticated request from user: {}", claims.sub);
                request
                    .extensions_mut()
                    .insert(AuthenticatedUser(claims.sub.clone()));
                request
                    .extensions_mut()
                    .insert(AuthenticatedRole(effective_role));
                request.extensions_mut().insert(AuthenticatedToken {
                    jti: claims.jti.clone(),
                    iat: claims.iat,
                });
                next.run(request).await
            }
            Err(e) => {
                debug!("Token validation failed: {}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthErrorResponse {
                        error: AuthErrorData {
                            code: "INVALID_TOKEN".to_string(),
                            message: "Invalid or expired token".to_string(),
                        },
                    }),
                )
                    .into_response()
            }
        },
        None => (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                error: AuthErrorData {
                    code: "MISSING_TOKEN".to_string(),
                    message: "Authentication required".to_string(),
                },
            }),
        )
            .into_response(),
    }
}

// --- Login rate limiting (L1) ---

/// Maximum number of usernames whose buckets are tracked. When full, the
/// stalest bucket is evicted so memory stays bounded.
const LOGIN_LIMITER_MAX_TRACKED: usize = 1000;

/// Per-username login rate limiter with a global backstop.
///
/// Keying by username means an attacker hammering "admin" cannot lock out
/// other accounts, and one account's failures do not spend the brute-force
/// budget of every other account. A generous global bucket still caps the
/// total guess rate across all usernames (including invented ones).
#[derive(Clone)]
pub struct LoginRateLimiter {
    /// username -> (remaining tokens, last refill instant)
    per_user: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>,
    >,
    global: RateLimiter,
    max_tokens: u32,
    refill_rate: f64,
    max_tracked: usize,
}

impl LoginRateLimiter {
    /// `per_user_max` tokens per `per_user_seconds` for each username, plus a
    /// `global_max` per `global_seconds` backstop shared by everyone.
    pub fn new(
        per_user_max: u32,
        per_user_seconds: u64,
        global_max: u32,
        global_seconds: u64,
    ) -> Self {
        Self {
            per_user: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            global: RateLimiter::new(global_max, global_seconds),
            max_tokens: per_user_max,
            refill_rate: per_user_max as f64 / per_user_seconds as f64,
            max_tracked: LOGIN_LIMITER_MAX_TRACKED,
        }
    }

    #[cfg(test)]
    fn with_max_tracked(mut self, max_tracked: usize) -> Self {
        self.max_tracked = max_tracked;
        self
    }

    /// Try to consume one attempt for `username`. Per-user bucket is checked
    /// first so a flood against one account cannot drain the global bucket
    /// for everyone else.
    pub fn try_acquire(&self, username: &str) -> bool {
        {
            let mut map = self.per_user.lock().unwrap();
            let now = std::time::Instant::now();

            // Bound memory: evict the stalest bucket before inserting a new
            // key. An evicted bucket resets to full, but the global backstop
            // still caps the total attempt rate.
            if !map.contains_key(username) && map.len() >= self.max_tracked {
                if let Some(stalest) = map
                    .iter()
                    .min_by_key(|(_, (_, last))| *last)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&stalest);
                }
            }

            let entry = map
                .entry(username.to_string())
                .or_insert((self.max_tokens, now));
            let elapsed = now.duration_since(entry.1).as_secs_f64();
            let refilled = (elapsed * self.refill_rate) as u32;
            if refilled > 0 {
                entry.0 = (entry.0 + refilled).min(self.max_tokens);
                entry.1 = now;
            }
            if entry.0 == 0 {
                return false;
            }
            entry.0 -= 1;
        }
        self.global.try_acquire()
    }
}

/// Combined state for the auth router: config, the login rate limiter, and the
/// DB handle the login path uses to validate credentials against the `users`
/// table.
#[derive(Clone)]
pub struct AuthState {
    pub config: AuthConfig,
    pub login_limiter: LoginRateLimiter,
    pub db: Arc<SqliteConnection>,
}

impl axum::extract::FromRef<AuthState> for AuthConfig {
    fn from_ref(state: &AuthState) -> Self {
        state.config.clone()
    }
}

impl axum::extract::FromRef<AuthState> for LoginRateLimiter {
    fn from_ref(state: &AuthState) -> Self {
        state.login_limiter.clone()
    }
}

impl axum::extract::FromRef<AuthState> for Arc<SqliteConnection> {
    fn from_ref(state: &AuthState) -> Self {
        state.db.clone()
    }
}

/// Create authentication router.
///
/// `/api/v1/auth/login` is rate-limited inside the handler: 5 attempts per
/// 60 seconds per username, with a global 50/60s backstop, so credential
/// brute-force is throttled without one account's failures locking out
/// everyone else. `/me` and `/logout` are not throttled — they are cheap
/// session operations the GUI may call freely.
pub fn auth_router(auth_config: AuthConfig, db: Arc<SqliteConnection>) -> Router {
    let state = AuthState {
        config: auth_config,
        login_limiter: LoginRateLimiter::new(5, 60, 50, 60),
        db,
    };

    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", axum::routing::get(get_current_user))
        .with_state(state)
}

// --- CSRF Protection ---

/// Cookie name for the CSRF double-submit token (readable by JS, not HttpOnly)
pub const CSRF_COOKIE_NAME: &str = "seance_csrf";

/// Header name the client must send with the CSRF token value
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// CSRF protection middleware (double-submit cookie pattern).
///
/// For GET/HEAD/OPTIONS requests: sets a CSRF cookie if not already present.
/// For POST/PUT/DELETE requests: validates that the `X-CSRF-Token` header
/// matches the `seance_csrf` cookie value.
/// When auth is disabled, CSRF validation is also skipped.
pub async fn csrf_middleware(
    State(auth_config): State<AuthConfig>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    // Skip CSRF when auth is disabled (development/testing)
    if !auth_config.enabled {
        return next.run(request).await;
    }

    let method = request.method().clone();

    // Safe methods: ensure CSRF cookie exists, then pass through
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        let mut response = next.run(request).await;
        // Set CSRF cookie if not already present
        if jar.get(CSRF_COOKIE_NAME).is_none() {
            let token = uuid::Uuid::new_v4().to_string();
            // Match the auth cookie's Secure logic so on HTTPS deployments the
            // CSRF token is not set/sent over plain HTTP (BUG-085).
            let secure_attr = if cookie_secure_from_env() {
                "; Secure"
            } else {
                ""
            };
            let cookie_value = format!(
                "{}={}; Path=/; SameSite=Strict; Max-Age=86400{}",
                CSRF_COOKIE_NAME, token, secure_attr
            );
            if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie_value) {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, hv);
            }
        }
        return response;
    }

    // Unsafe methods: validate CSRF token
    let cookie_token = jar.get(CSRF_COOKIE_NAME).map(|c| c.value().to_string());
    let header_token = request
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|h| h.to_str().ok())
        .map(String::from);

    match (cookie_token, header_token) {
        (Some(cookie_val), Some(header_val))
            if !cookie_val.is_empty() && cookie_val == header_val =>
        {
            // Token matches — allow request
            next.run(request).await
        }
        _ => {
            debug!("CSRF validation failed for {} {}", method, request.uri());
            (
                StatusCode::FORBIDDEN,
                Json(AuthErrorResponse {
                    error: AuthErrorData {
                        code: "CSRF_VALIDATION_FAILED".to_string(),
                        message: "Missing or invalid CSRF token".to_string(),
                    },
                }),
            )
                .into_response()
        }
    }
}

// --- Rate Limiting ---

/// Simple token-bucket rate limiter state (shared across clones via Arc).
#[derive(Clone)]
pub struct RateLimiter {
    /// Remaining tokens and last refill timestamp.
    state: std::sync::Arc<std::sync::Mutex<(u32, std::time::Instant)>>,
    /// Maximum tokens (burst capacity).
    max_tokens: u32,
    /// Tokens added per second.
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    /// `max_tokens`: burst capacity. `per_seconds`: refill period for all tokens.
    pub fn new(max_tokens: u32, per_seconds: u64) -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new((
                max_tokens,
                std::time::Instant::now(),
            ))),
            max_tokens,
            refill_rate: max_tokens as f64 / per_seconds as f64,
        }
    }

    /// Try to consume one token. Returns true if allowed.
    pub fn try_acquire(&self) -> bool {
        let mut guard = self.state.lock().unwrap();
        let (ref mut tokens, ref mut last_refill) = *guard;
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        let refilled = (elapsed * self.refill_rate) as u32;
        if refilled > 0 {
            *tokens = (*tokens + refilled).min(self.max_tokens);
            *last_refill = now;
        }
        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Rate limiting middleware for ingestion endpoints.
/// Rejects requests with 429 Too Many Requests when the bucket is exhausted.
pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    if limiter.try_acquire() {
        next.run(request).await
    } else {
        warn!(
            "Rate limit exceeded for {} {}",
            request.method(),
            request.uri()
        );
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(AuthErrorResponse {
                error: AuthErrorData {
                    code: "RATE_LIMIT_EXCEEDED".to_string(),
                    message: "Too many requests. Please try again later.".to_string(),
                },
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    // The env mutex is held across the await on purpose: it serialises tests
    // that mutate process environment, and releasing it before the request
    // completes would let another test change `SEANCE_COOKIE_SECURE` mid-flight.
    #![allow(clippy::await_holding_lock)]

    use super::*;

    /// The bcrypt hash of the test password, computed once.
    ///
    /// `DEFAULT_COST` is twelve rounds — roughly 300 ms, deliberately, because
    /// that is what makes a stolen hash expensive to attack. Paying it in
    /// `test_config` paid it once per test rather than once per suite, which
    /// is a third of a second of nothing on every auth test that runs.
    ///
    /// Computed at the real cost rather than lowered to cost 4: these tests
    /// exercise the verify path, and verifying against a hash produced at a
    /// different cost would exercise a hash no deployment ever stores.
    fn test_password_hash() -> &'static str {
        static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        HASH.get_or_init(|| hash("password123", DEFAULT_COST).expect("bcrypt"))
    }

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "test-secret".to_string(),
            admin_username: "admin".to_string(),
            admin_password_hash: test_password_hash().to_string(),
            enabled: true,
        }
    }

    /// In-memory DB for auth-router tests that need the login-path DB handle.
    async fn test_db() -> Arc<SqliteConnection> {
        use seance_core::db::DatabaseConnection;
        let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        Arc::new(db)
    }

    #[test]
    fn test_validate_credentials_correct() {
        let config = test_config();
        assert!(config.validate_credentials("admin", "password123"));
    }

    #[test]
    fn test_validate_credentials_wrong_password() {
        let config = test_config();
        assert!(!config.validate_credentials("admin", "wrongpassword"));
    }

    #[test]
    fn test_validate_credentials_wrong_username() {
        let config = test_config();
        assert!(!config.validate_credentials("notadmin", "password123"));
    }

    #[test]
    fn test_generate_and_validate_token() {
        let config = test_config();
        let (token, _) = config.generate_token("admin", "admin").unwrap();
        let claims = config.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "admin");
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn test_validate_invalid_token() {
        let config = test_config();
        let result = config.validate_token("invalid-token");
        assert!(result.is_err());
    }

    // -- RateLimiter unit tests ---------------------------------------------

    #[test]
    fn rate_limiter_allows_up_to_max_tokens() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        // 4th acquisition is denied — bucket empty, no time to refill.
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        // 2 tokens per 1 second means 1 token every 500ms.
        let limiter = RateLimiter::new(2, 1);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
        // Wait for one refill window.
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(
            limiter.try_acquire(),
            "should have refilled at least 1 token"
        );
    }

    #[test]
    fn rate_limiter_state_is_shared_across_clones() {
        // RateLimiter is Clone — multiple clones share the same bucket state.
        // This is critical: if every middleware invocation got a fresh bucket,
        // the limiter wouldn't actually limit anything.
        let a = RateLimiter::new(2, 60);
        let b = a.clone();
        assert!(a.try_acquire());
        assert!(b.try_acquire());
        // Both clones drew from the same bucket; the 3rd request fails.
        assert!(!a.try_acquire());
        assert!(!b.try_acquire());
    }

    // -- CSRF middleware behavior (smoke tests) ------------------------------

    #[tokio::test]
    async fn csrf_middleware_passes_through_when_auth_disabled() {
        // When auth.enabled = false, all CSRF checks are skipped (dev mode).
        let mut cfg = test_config();
        cfg.enabled = false;

        let app = axum::Router::new()
            .route("/", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(cfg, csrf_middleware));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_middleware_rejects_unsafe_method_without_token() {
        // POST without matching header+cookie → 403.
        let app = axum::Router::new()
            .route("/", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                test_config(),
                csrf_middleware,
            ));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_middleware_accepts_matching_token() {
        let app = axum::Router::new()
            .route("/", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                test_config(),
                csrf_middleware,
            ));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .header("cookie", format!("{}=tok123", CSRF_COOKIE_NAME))
            .header(CSRF_HEADER_NAME, "tok123")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_middleware_rejects_mismatched_token() {
        // Common attack pattern: attacker forges a Cookie value via a different
        // origin or includes a stale header. Double-submit catches this.
        let app = axum::Router::new()
            .route("/", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                test_config(),
                csrf_middleware,
            ));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .header("cookie", format!("{}=actual_token", CSRF_COOKIE_NAME))
            .header(CSRF_HEADER_NAME, "stolen_token")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_middleware_rejects_empty_token() {
        // Empty-string cookie that happens to also equal the empty header
        // must not be accepted (otherwise a missing cookie defeats CSRF).
        let app = axum::Router::new()
            .route("/", post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                test_config(),
                csrf_middleware,
            ));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .header("cookie", format!("{}=", CSRF_COOKIE_NAME))
            .header(CSRF_HEADER_NAME, "")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_middleware_get_request_sets_cookie_if_missing() {
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                test_config(),
                csrf_middleware,
            ));

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // The response should include a Set-Cookie for the CSRF cookie.
        let cookies: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(
            cookies.iter().any(|c| c.contains(CSRF_COOKIE_NAME)),
            "expected Set-Cookie with {}; got {:?}",
            CSRF_COOKIE_NAME,
            cookies
        );
    }

    // -- auth_middleware user attribution -------------------------------------

    /// Router whose handler echoes the AuthenticatedUser extension.
    fn user_echo_router(cfg: AuthConfig, db: Arc<SqliteConnection>) -> axum::Router {
        async fn echo_user(axum::Extension(user): axum::Extension<AuthenticatedUser>) -> String {
            user.0
        }

        axum::Router::new()
            .route("/", axum::routing::get(echo_user))
            .layer(axum::middleware::from_fn_with_state(
                AuthLayerState { config: cfg, db },
                auth_middleware,
            ))
    }

    /// Router whose handler echoes the AuthenticatedRole extension.
    fn role_echo_router(cfg: AuthConfig, db: Arc<SqliteConnection>) -> axum::Router {
        async fn echo_role(axum::Extension(role): axum::Extension<AuthenticatedRole>) -> String {
            role.0
        }

        axum::Router::new()
            .route("/", axum::routing::get(echo_role))
            .layer(axum::middleware::from_fn_with_state(
                AuthLayerState { config: cfg, db },
                auth_middleware,
            ))
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn get_req(uri: &str, token: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn auth_middleware_inserts_authenticated_username() {
        let cfg = test_config();
        let db = test_db().await;
        db.create_user("alice", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let (token, _) = cfg.generate_token("alice", "examiner").unwrap();
        let app = user_echo_router(cfg, db);

        let resp = tower::ServiceExt::oneshot(app, get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "alice");
    }

    #[tokio::test]
    async fn auth_middleware_inserts_local_user_when_auth_disabled() {
        let mut cfg = test_config();
        cfg.enabled = false;
        let db = test_db().await;
        let app = user_echo_router(cfg, db);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "local");
    }

    #[tokio::test]
    async fn auth_middleware_rejects_deactivated_user() {
        // A signed, unexpired token must stop working the moment the account is
        // deactivated -- not at token expiry (BUG-004).
        let cfg = test_config();
        let db = test_db().await;
        let id = db
            .create_user("mallory", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let (token, _) = cfg.generate_token("mallory", "examiner").unwrap();
        db.set_user_active(id, false).await.unwrap();

        let app = user_echo_router(cfg, db);
        let resp = tower::ServiceExt::oneshot(app, get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_middleware_uses_db_role_not_token_role() {
        // A token minted while the user was admin must reflect a later demotion
        // immediately: the injected role comes from the DB, not the claim.
        let cfg = test_config();
        let db = test_db().await;
        let id = db
            .create_user("dana", &hash_password("pw").unwrap(), "admin")
            .await
            .unwrap();
        let (stale_admin_token, _) = cfg.generate_token("dana", "admin").unwrap();
        db.update_user_role(id, "examiner").await.unwrap();

        let app = role_echo_router(cfg, db);
        let resp = tower::ServiceExt::oneshot(app, get_req("/", &stale_admin_token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_string(resp).await,
            "examiner",
            "demotion must take effect before token expiry"
        );
    }

    #[tokio::test]
    async fn auth_middleware_rejects_deleted_user() {
        // A hard-deleted account's signed token must stop working immediately.
        // A deleted admin would otherwise keep admin (AdminUser and
        // require_case_access short-circuit on role == "admin") until the JWT
        // expires up to 24h later (BUG-044).
        let cfg = test_config();
        let db = test_db().await;
        let id = db
            .create_user("victor", &hash_password("pw").unwrap(), "admin")
            .await
            .unwrap();
        let (token, _) = cfg.generate_token("victor", "admin").unwrap();
        db.delete_user(id).await.unwrap();

        let app = role_echo_router(cfg, db);
        let resp = tower::ServiceExt::oneshot(app, get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a deleted user's token must be rejected, not trusted until expiry"
        );
    }

    // -- Env-dependent config tests (serialized: env vars are process-global) --

    /// Every env-touching test in this crate shares one lock; see
    /// [`crate::TEST_ENV_LOCK`] for why it cannot be a per-module one.
    use crate::TEST_ENV_LOCK as ENV_MUTEX;

    #[test]
    fn from_env_generates_random_secret_when_unset() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SEANCE_JWT_SECRET");
        let a = AuthConfig::from_env();
        let b = AuthConfig::from_env();
        // Each process start without a configured secret gets a fresh one —
        // never the old forgeable hardcoded default.
        assert_ne!(a.jwt_secret, b.jwt_secret);
        assert!(
            a.jwt_secret.len() >= 32,
            "secret too short: {}",
            a.jwt_secret.len()
        );
        assert_ne!(a.jwt_secret, "seance-default-secret-change-in-production");
    }

    #[test]
    fn from_env_uses_configured_secret() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SEANCE_JWT_SECRET", "configured-secret");
        let a = AuthConfig::from_env();
        let b = AuthConfig::from_env();
        std::env::remove_var("SEANCE_JWT_SECRET");
        assert_eq!(a.jwt_secret, "configured-secret");
        assert_eq!(b.jwt_secret, "configured-secret");
    }

    #[test]
    fn an_empty_jwt_secret_is_refused_as_a_signing_key() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Both spellings of "the operator exported the variable but gave it no
        // value". Either used to become the HS256 key verbatim, and a key
        // anyone can guess is a key anyone can sign an admin token with.
        std::env::set_var("SEANCE_JWT_SECRET", "");
        let empty = AuthConfig::from_env();
        std::env::set_var("SEANCE_JWT_SECRET", "   ");
        let blank = AuthConfig::from_env();
        std::env::remove_var("SEANCE_JWT_SECRET");

        for cfg in [&empty, &blank] {
            assert!(
                cfg.jwt_secret.trim().len() >= 32,
                "an empty SEANCE_JWT_SECRET must be replaced by a random one, got {:?}",
                cfg.jwt_secret
            );
        }
        // Replaced per process, exactly like the unset case.
        assert_ne!(empty.jwt_secret, blank.jwt_secret);
    }

    #[test]
    fn an_env_admin_password_below_the_minimum_is_not_pinned() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // An empty value hashes to a valid bcrypt digest of "", which
        // bootstrap_admin used to read as an operator-chosen credential and
        // seed with no forced rotation: a permanent password-less admin.
        for weak in ["", "   ", "short"] {
            std::env::set_var("SEANCE_ADMIN_PASSWORD", weak);
            let cfg = AuthConfig::from_env();
            assert!(
                cfg.admin_password_hash.is_empty(),
                "{:?} must not be pinned as the admin password",
                weak
            );
        }

        // A real password is still honoured, verbatim.
        std::env::set_var("SEANCE_ADMIN_PASSWORD", "a-real-password");
        let cfg = AuthConfig::from_env();
        std::env::remove_var("SEANCE_ADMIN_PASSWORD");
        assert!(!cfg.admin_password_hash.is_empty());
        assert!(verify("a-real-password", &cfg.admin_password_hash).unwrap());
    }

    #[test]
    fn cookie_secure_flag_from_env() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SEANCE_COOKIE_SECURE");
        assert!(
            !cookie_secure_from_env(),
            "default must be false for localhost HTTP"
        );
        for truthy in ["1", "true", "TRUE", "yes"] {
            std::env::set_var("SEANCE_COOKIE_SECURE", truthy);
            assert!(
                cookie_secure_from_env(),
                "{:?} should enable Secure",
                truthy
            );
        }
        for falsy in ["0", "false", "no", ""] {
            std::env::set_var("SEANCE_COOKIE_SECURE", falsy);
            assert!(
                !cookie_secure_from_env(),
                "{:?} should not enable Secure",
                falsy
            );
        }
        std::env::remove_var("SEANCE_COOKIE_SECURE");
    }

    // -- LoginRateLimiter (L1) ------------------------------------------------

    #[test]
    fn login_limiter_is_keyed_per_username() {
        let limiter = LoginRateLimiter::new(3, 60, 100, 60);
        // Alice exhausts her bucket...
        assert!(limiter.try_acquire("alice"));
        assert!(limiter.try_acquire("alice"));
        assert!(limiter.try_acquire("alice"));
        assert!(!limiter.try_acquire("alice"));
        // ...but Bob (and the admin) are unaffected.
        assert!(limiter.try_acquire("bob"));
        assert!(limiter.try_acquire("admin"));
    }

    #[test]
    fn login_limiter_global_cap_still_triggers() {
        // Per-user budget is generous, global cap is 4: spreading attempts
        // across many usernames still gets throttled.
        let limiter = LoginRateLimiter::new(100, 60, 4, 60);
        assert!(limiter.try_acquire("u1"));
        assert!(limiter.try_acquire("u2"));
        assert!(limiter.try_acquire("u3"));
        assert!(limiter.try_acquire("u4"));
        assert!(!limiter.try_acquire("u5"), "global backstop should trip");
    }

    #[test]
    fn login_limiter_evicts_stalest_entry_at_cap() {
        let limiter = LoginRateLimiter::new(1, 60, 100, 60).with_max_tracked(2);
        assert!(limiter.try_acquire("a"));
        assert!(limiter.try_acquire("b"));
        // Third username forces eviction of the stalest bucket; map stays bounded.
        assert!(limiter.try_acquire("c"));
        let tracked = limiter.per_user.lock().unwrap().len();
        assert!(tracked <= 2, "tracked {} usernames, cap is 2", tracked);
    }

    // -- /auth/me token extraction --------------------------------------------

    #[tokio::test]
    async fn me_accepts_bearer_token() {
        let cfg = test_config();
        let db = test_db().await;
        db.create_user("alice", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        // Minted AFTER the row exists. A token minted before the account was
        // created pre-dates its birth stamp and is refused (`SEC-006`), and the
        // bcrypt hash above takes long enough to cross a second boundary.
        let (token, _) = cfg.generate_token("alice", "user").unwrap();
        let app = auth_router(cfg, db);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/auth/me")
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"authenticated\":true"), "body: {}", body);
        assert!(body.contains("alice"), "body: {}", body);
    }

    #[tokio::test]
    async fn me_still_accepts_cookie() {
        let cfg = test_config();
        let db = test_db().await;
        db.create_user("bob", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        // Minted AFTER the row exists. A token minted before the account was
        // created pre-dates its birth stamp and is refused (`SEC-006`), and the
        // bcrypt hash above takes long enough to cross a second boundary.
        let (token, _) = cfg.generate_token("bob", "user").unwrap();
        let app = auth_router(cfg, db);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/auth/me")
            .header("cookie", format!("{}={}", AUTH_COOKIE_NAME, token))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"authenticated\":true"), "body: {}", body);
        assert!(body.contains("bob"), "body: {}", body);
    }

    /// GET /auth/me with the given token against a router over `db`.
    async fn me_body(cfg: AuthConfig, db: Arc<SqliteConnection>, token: &str) -> String {
        let app = auth_router(cfg, db);
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/auth/me")
            .header(AUTHORIZATION, format!("Bearer {}", token))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        body_string(resp).await
    }

    #[tokio::test]
    async fn me_reports_a_deactivated_account_as_unauthenticated() {
        // B2-058: the token is still signed and unexpired, but the account is
        // gone as far as every protected endpoint is concerned. /me must agree,
        // or the UI keeps showing a signed-in examiner who can do nothing.
        let cfg = test_config();
        let (token, _) = cfg.generate_token("carol", "examiner").unwrap();
        let db = test_db().await;
        let id = db
            .create_user("carol", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        db.set_user_active(id, false).await.unwrap();

        let body = me_body(cfg, db, &token).await;
        assert!(body.contains("\"authenticated\":false"), "body: {}", body);
    }

    #[tokio::test]
    async fn me_reports_a_deleted_account_as_unauthenticated() {
        let cfg = test_config();
        let (token, _) = cfg.generate_token("dan", "admin").unwrap();
        // Never created: a signed token for an account with no row must not
        // pass, except for the env-admin bootstrap on an empty users table.
        let db = test_db().await;
        db.create_user("someone_else", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();

        let body = me_body(cfg, db, &token).await;
        assert!(body.contains("\"authenticated\":false"), "body: {}", body);
    }

    #[tokio::test]
    async fn me_answers_with_the_database_role_not_the_token_role() {
        // A demoted admin's old token still claims "admin"; /me must report the
        // role the database now holds.
        let cfg = test_config();
        let db = test_db().await;
        db.create_user("erika", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        // Minted AFTER the row exists. A token minted before the account was
        // created pre-dates its birth stamp and is refused (`SEC-006`), and the
        // bcrypt hash above takes long enough to cross a second boundary.
        let (token, _) = cfg.generate_token("erika", "admin").unwrap();

        let body = me_body(cfg, db, &token).await;
        assert!(body.contains("\"authenticated\":true"), "body: {}", body);
        assert!(body.contains("\"role\":\"examiner\""), "body: {}", body);
    }

    #[test]
    fn rate_limiter_caps_refill_at_max_tokens() {
        // After a long quiet period, the bucket should be at most `max_tokens`
        // — it should NOT accumulate unlimited credits.
        let limiter = RateLimiter::new(3, 1);
        // Drain.
        limiter.try_acquire();
        limiter.try_acquire();
        limiter.try_acquire();
        // Sleep long enough that the refill would, unclamped, exceed max.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        // Should still only allow max_tokens (3) consecutive requests.
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(
            !limiter.try_acquire(),
            "burst should be capped at max_tokens"
        );
    }

    // -- DB-backed credential validation (authenticate_user) ------------------

    #[tokio::test]
    async fn authenticate_user_success_returns_db_role() {
        let db = test_db().await;
        let cfg = test_config();
        db.create_user("erin", &hash_password("examinerpw1").unwrap(), "examiner")
            .await
            .unwrap();

        let result = authenticate_user(&db, &cfg, "erin", "examinerpw1").await;
        assert_eq!(
            result,
            Some(("erin".to_string(), "examiner".to_string(), false))
        );
    }

    #[tokio::test]
    async fn authenticate_user_wrong_password_fails() {
        let db = test_db().await;
        let cfg = test_config();
        db.create_user("erin", &hash_password("examinerpw1").unwrap(), "examiner")
            .await
            .unwrap();

        assert!(authenticate_user(&db, &cfg, "erin", "wrong")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn authenticate_user_deactivated_fails() {
        let db = test_db().await;
        let cfg = test_config();
        let id = db
            .create_user("erin", &hash_password("examinerpw1").unwrap(), "examiner")
            .await
            .unwrap();
        db.set_user_active(id, false).await.unwrap();

        assert!(
            authenticate_user(&db, &cfg, "erin", "examinerpw1")
                .await
                .is_none(),
            "deactivated user must not authenticate even with the correct password"
        );
    }

    #[tokio::test]
    async fn authenticate_user_env_admin_fallback_only_while_table_empty() {
        let db = test_db().await;
        let cfg = test_config(); // admin_password_hash = hash("password123")

        // Empty table: env admin fallback works (bootstrap race). The fallback
        // never carries a must-change flag (false).
        assert_eq!(
            authenticate_user(&db, &cfg, "admin", "password123").await,
            Some(("admin".to_string(), "admin".to_string(), false))
        );

        // Once a user exists, the env admin fallback is inert.
        db.create_user("erin", &hash_password("examinerpw1").unwrap(), "examiner")
            .await
            .unwrap();
        assert!(
            authenticate_user(&db, &cfg, "admin", "password123")
                .await
                .is_none(),
            "env admin fallback must stop once the users table is seeded"
        );
    }

    #[tokio::test]
    async fn admin_user_extractor_rejects_non_admin() {
        async fn guarded(_admin: AdminUser) -> &'static str {
            "ok"
        }

        // Route behind auth_middleware so extensions (user + role) are set.
        let cfg = test_config();
        let db = test_db().await;
        db.create_user("erin", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let (token, _) = cfg.generate_token("erin", "examiner").unwrap();
        let app = axum::Router::new()
            .route("/", axum::routing::get(guarded))
            .layer(axum::middleware::from_fn_with_state(
                AuthLayerState { config: cfg, db },
                auth_middleware,
            ));

        let resp = tower::ServiceExt::oneshot(app, get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_user_extractor_admits_admin() {
        async fn guarded(_admin: AdminUser) -> &'static str {
            "ok"
        }

        let cfg = test_config();
        let db = test_db().await;
        db.create_user("root", &hash_password("pw").unwrap(), "admin")
            .await
            .unwrap();
        let (token, _) = cfg.generate_token("root", "admin").unwrap();
        let app = axum::Router::new()
            .route("/", axum::routing::get(guarded))
            .layer(axum::middleware::from_fn_with_state(
                AuthLayerState { config: cfg, db },
                auth_middleware,
            ));

        let resp = tower::ServiceExt::oneshot(app, get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn must_change_token_blocked_from_other_users_password() {
        // A forced-rotation token may reach only the caller's OWN password
        // endpoint, never another user's (BUG-019).
        async fn ok() -> &'static str {
            "ok"
        }
        let cfg = test_config();
        let db = test_db().await;
        let self_id = db
            .create_user("frank", &hash_password("pw").unwrap(), "admin")
            .await
            .unwrap();
        let other_id = db
            .create_user("gina", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let (token, _) = cfg.generate_token_full("frank", "admin", true).unwrap();

        let app = axum::Router::new()
            .route("/api/v1/users/:id/password", axum::routing::get(ok))
            .layer(axum::middleware::from_fn_with_state(
                AuthLayerState { config: cfg, db },
                auth_middleware,
            ));

        // Own password endpoint: allowed through the must-change gate.
        let own = format!("/api/v1/users/{}/password", self_id);
        let resp = tower::ServiceExt::oneshot(app.clone(), get_req(&own, &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Another user's password endpoint: 403 until rotation.
        let other = format!("/api/v1/users/{}/password", other_id);
        let resp = tower::ServiceExt::oneshot(app, get_req(&other, &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Mint a token with a chosen `iat`, so the same-second boundary against
    /// `password_changed_at` can be exercised deterministically.
    fn token_with_iat(cfg: &AuthConfig, username: &str, role: &str, iat: u64) -> String {
        let claims = Claims {
            sub: username.to_string(),
            exp: iat + 3600,
            iat,
            role: role.to_string(),
            must_change: false,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .unwrap()
    }

    /// An expired token must be refused the moment it expires.
    ///
    /// `Validation::default()` carries a **60-second leeway**, so a token stayed
    /// acceptable for a minute past its `exp`. The revoked-token sweep deletes a
    /// row once `expires_at < now`, so between `exp` and `exp + 60` a captured
    /// copy of a LOGGED-OUT token passed signature and expiry checks, found no
    /// revocation row, and was accepted. The two windows have to not overlap;
    /// this closes the validator's end (the sweep keeps a margin at the other).
    #[test]
    fn an_expired_token_is_refused_immediately_not_a_minute_later() {
        let cfg = test_config();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Expired 10 seconds ago — well inside the default 60s leeway.
        let claims = Claims {
            sub: "ivy".to_string(),
            exp: now - 10,
            iat: now - 3610,
            role: "examiner".to_string(),
            must_change: false,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .unwrap();

        assert!(
            cfg.validate_token(&token).is_err(),
            "a token 10s past its exp must be refused; the default 60s leeway \
             would accept it, and its revocation row may already be swept"
        );

        // ... and one still inside its life is of course accepted.
        let live = token_with_iat(&cfg, "ivy", "examiner", now);
        assert!(cfg.validate_token(&live).is_ok());
    }

    #[tokio::test]
    async fn token_issued_in_the_password_change_second_is_superseded() {
        // Both stamps are whole seconds, so `iat < password_changed_at` let a
        // session minted inside that same second survive the rotation (BUG-249).
        let cfg = test_config();
        let db = test_db().await;
        let id = db
            .create_user("ivy", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        db.update_user_password(id, &hash_password("rotated-pw").unwrap())
            .await
            .unwrap();
        let changed_at = db
            .get_user_by_username("ivy")
            .await
            .unwrap()
            .expect("user row")
            .password_changed_at as u64;
        assert!(changed_at > 0, "the change must be stamped");

        let same_second = token_with_iat(&cfg, "ivy", "examiner", changed_at);
        let after = token_with_iat(&cfg, "ivy", "examiner", changed_at + 1);
        let app = user_echo_router(cfg, db);

        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &same_second))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a token minted in the rotation second must not survive it"
        );
        assert!(body_string(resp).await.contains("SESSION_SUPERSEDED"));

        // A token minted after the change second still works.
        let resp = tower::ServiceExt::oneshot(app, get_req("/", &after))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn reactivating_a_user_does_not_revive_the_sessions_that_were_live_before_deactivation() {
        // SEC-002. The middleware refuses a token for an inactive user on every
        // request, so deactivation looked like it ended the session. It did not:
        // it suspended it. Deactivation stamped nothing, so the refusal lasted
        // exactly as long as the account stayed deactivated, and reactivating
        // brought every token minted before the deactivation back to life -- a
        // session nobody re-authenticated, attributing work to an examiner on a
        // machine whose whole point is knowing who did what.
        let cfg = test_config();
        let db = test_db().await;
        let id = db
            .create_user("jane", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();

        // A session held from before the deactivation.
        let (token, _) = cfg.generate_token("jane", "examiner").unwrap();
        let app = user_echo_router(cfg.clone(), db.clone());

        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "the session starts live");

        // Deactivate: refused, as it always was.
        db.set_user_active(id, false).await.unwrap();
        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(body_string(resp).await.contains("ACCOUNT_INACTIVE"));

        // Reactivate. This is the line the defect turned on: before the fix the
        // next request was 200.
        db.set_user_active(id, true).await.unwrap();
        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a token held from before the deactivation must not come back with the account"
        );
        assert!(body_string(resp).await.contains("SESSION_SUPERSEDED"));

        // And the account itself is usable again: a fresh login works. The stamp
        // ends sessions, not the user.
        let stamp = db
            .get_user_by_username("jane")
            .await
            .unwrap()
            .expect("user row")
            .sessions_invalid_before as u64;
        assert!(stamp > 0, "deactivation must stamp");
        let fresh = token_with_iat(&cfg, "jane", "examiner", stamp + 1);
        let resp = tower::ServiceExt::oneshot(app, get_req("/", &fresh))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_token_minted_in_the_deactivation_second_does_not_survive_it() {
        // The same whole-second boundary `password_changed_at` has (BUG-249):
        // `iat` and the stamp are both whole Unix seconds, so a token minted
        // inside the deactivation second is indistinguishable from one minted
        // just before it. It is refused, and a token from the next second is not.
        let cfg = test_config();
        let db = test_db().await;
        let id = db
            .create_user("kelly", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        db.set_user_active(id, false).await.unwrap();
        db.set_user_active(id, true).await.unwrap();

        let stamp = db
            .get_user_by_username("kelly")
            .await
            .unwrap()
            .expect("user row")
            .sessions_invalid_before as u64;

        let app = user_echo_router(cfg.clone(), db);
        let same_second = token_with_iat(&cfg, "kelly", "examiner", stamp);
        let after = token_with_iat(&cfg, "kelly", "examiner", stamp + 1);

        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &same_second))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(body_string(resp).await.contains("SESSION_SUPERSEDED"));

        let resp = tower::ServiceExt::oneshot(app, get_req("/", &after))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn reactivation_does_not_move_the_stamp_forward() {
        // Reactivating must not re-stamp: there are no tokens to invalidate from
        // the deactivated window (every request in it was refused), and moving
        // the stamp to the reactivation instant would kill the session the
        // examiner creates by signing back in during that same second.
        let db = test_db().await;
        let id = db
            .create_user("liam", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        db.set_user_active(id, false).await.unwrap();
        let after_deactivation = db
            .get_user_by_username("liam")
            .await
            .unwrap()
            .expect("user row")
            .sessions_invalid_before;

        db.set_user_active(id, true).await.unwrap();
        let after_reactivation = db
            .get_user_by_username("liam")
            .await
            .unwrap()
            .expect("user row")
            .sessions_invalid_before;

        assert_eq!(
            after_deactivation, after_reactivation,
            "reactivation restores the account, and must leave the stamp where deactivation put it"
        );
    }

    #[tokio::test]
    async fn a_user_never_deactivated_keeps_their_session() {
        // A new row is born with `sessions_invalid_before` set to the second
        // before its creation (`SEC-006`): it refuses every token minted for
        // the username before the account existed and nothing minted for the
        // account itself. So the stamp is not 0 -- 0 is still "never", as
        // `password_changed_at` treats it, and the guard still skips it -- but
        // it must sit strictly before any token this account can be issued.
        let cfg = test_config();
        let db = test_db().await;
        db.create_user("mia", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();

        let row = db
            .get_user_by_username("mia")
            .await
            .unwrap()
            .expect("user row");
        let (token, exp) = cfg.generate_token("mia", "examiner").unwrap();
        let iat = exp - TOKEN_EXPIRATION_SECS;
        assert!(
            row.sessions_invalid_before > 0,
            "a new user carries a birth stamp, not 0"
        );
        assert!(
            (row.sessions_invalid_before as u64) < iat,
            "the birth stamp ({}) must precede the first token minted for the account ({})",
            row.sessions_invalid_before,
            iat
        );

        let app = user_echo_router(cfg, db);
        let resp = tower::ServiceExt::oneshot(app, get_req("/", &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn me_carries_the_users_theme_so_the_first_paint_is_theirs() {
        // The theme travels with the identity rather than on a second request:
        // the answer that says who you are says how you want to see it, so
        // reconciling the browser's cached copy costs no extra round trip and
        // no flash.
        let cfg = test_config();
        let db = test_db().await;
        let id = db
            .create_user("ivy", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let (token, _) = cfg.generate_token("ivy", "examiner").unwrap();

        // Never chosen: null, not the default spelled out.
        let body = me_body(cfg.clone(), db.clone(), &token).await;
        assert!(body.contains("\"theme\":null"), "{body}");

        db.set_user_theme(id, Some("nature:light")).await.unwrap();
        let body = me_body(cfg, db, &token).await;
        assert!(body.contains("\"theme\":\"nature:light\""), "{body}");
    }

    /// The theme endpoint writes against the AUTHENTICATED identity and against
    /// nothing in the body.
    ///
    /// The body carries only the value; there is no user field to spoof, and
    /// this pins that there never is one. A preference endpoint that took a
    /// username would be a way to reach into another examiner's account, which
    /// on this product is a custody surface and not a cosmetic one.
    #[tokio::test]
    async fn setting_a_theme_changes_the_callers_own_and_no_one_elses() {
        let db = test_db().await;
        let ivy = db
            .create_user("ivy", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let jack = db
            .create_user("jack", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        db.set_user_theme(jack, Some("relax:dark")).await.unwrap();

        // Written as the middleware would: the identity comes from the request
        // extension, and the body is only the value.
        db.set_user_theme(ivy, Some("cyber:light")).await.unwrap();

        assert_eq!(
            db.get_user_theme("ivy").await.unwrap().as_deref(),
            Some("cyber:light")
        );
        assert_eq!(
            db.get_user_theme("jack").await.unwrap().as_deref(),
            Some("relax:dark"),
            "another examiner's preference must be untouched"
        );

        // And the request body has exactly one field, so there is nothing to
        // spoof: a body naming a user is not a shape this endpoint can parse.
        let parsed: Result<ThemeRequest, _> = serde_json::from_str(r#"{"theme":"opus:dark"}"#);
        assert!(parsed.is_ok());
        let with_user: Result<ThemeRequest, _> =
            serde_json::from_str(r#"{"theme":"opus:dark","username":"jack"}"#);
        assert!(
            with_user.is_ok(),
            "an extra field is ignored rather than honoured"
        );
        assert_eq!(with_user.unwrap().theme.as_deref(), Some("opus:dark"));
    }

    /// Deleting an account and re-creating its username must not revive the
    /// old account's tokens.
    ///
    /// The middleware keys a token on `sub`, the username, and `Claims` carries
    /// no user id. A deleted user's token was refused only because no row was
    /// found; re-create the username and the lookup succeeds against a row
    /// whose two invalidation stamps are 0 — nothing to fail against — and
    /// every un-revoked token minted for the OLD account is accepted as the
    /// new one, with the new row's role. `SEC-002`'s class, through the one
    /// route its fix did not cover. A row is now born with the stamp.
    #[tokio::test]
    async fn recreating_a_deleted_username_does_not_revive_the_old_accounts_tokens() {
        let cfg = test_config();
        let db = test_db().await;
        let old_id = db
            .create_user("nora", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let (old_token, _) = cfg.generate_token("nora", "examiner").unwrap();
        let app = user_echo_router(cfg.clone(), db.clone());

        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &old_token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "live before deletion");

        assert!(db.delete_user(old_id).await.unwrap());
        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &old_token))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "refused while deleted"
        );

        // A second account with the same name, a second later so the stamps
        // are strictly after the old token's `iat` in whole seconds.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let new_id = db
            .create_user("nora", &hash_password("other-pw").unwrap(), "admin")
            .await
            .unwrap();
        assert_ne!(old_id, new_id);

        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/", &old_token))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a token minted for the deleted account must not be accepted as the new one"
        );

        // And the new account itself signs in: the stamp ends old sessions, not
        // the user.
        let stamp = db
            .get_user_by_username("nora")
            .await
            .unwrap()
            .expect("row")
            .sessions_invalid_before as u64;
        assert!(stamp > 0, "a new row is born with the stamp");
        let fresh = token_with_iat(&cfg, "nora", "admin", stamp + 1);
        let resp = tower::ServiceExt::oneshot(app, get_req("/", &fresh))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The liveness question the SSE stream asks on its tick gives the same
    /// answer the middleware gives a request at that moment.
    #[tokio::test]
    async fn session_still_live_agrees_with_the_middleware() {
        let db = test_db().await;
        let id = db
            .create_user("oren", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = AuthenticatedToken {
            jti: uuid::Uuid::new_v4().to_string(),
            // Minted after the creation stamp.
            iat: now + 2,
        };

        assert!(
            session_still_live(&db, "oren", &token).await,
            "a live session is live"
        );

        // Deactivated: not live, and reactivating does not bring it back.
        db.set_user_active(id, false).await.unwrap();
        assert!(!session_still_live(&db, "oren", &token).await);
        db.set_user_active(id, true).await.unwrap();
        // The deactivation stamp is `now` and the token's iat is `now + 2`, so
        // this token post-dates it and is live again; one minted before it is
        // not.
        assert!(session_still_live(&db, "oren", &token).await);
        let older = AuthenticatedToken {
            jti: token.jti.clone(),
            iat: now - 5,
        };
        assert!(!session_still_live(&db, "oren", &older).await);

        // Revoked: not live.
        db.revoke_token(
            &token.jti,
            Some(id),
            "oren",
            (now + 3600) as i64,
            now as i64,
        )
        .await
        .unwrap();
        assert!(!session_still_live(&db, "oren", &token).await);

        // No jti at all — a legacy token — is never live.
        let bare = AuthenticatedToken {
            jti: String::new(),
            iat: now + 2,
        };
        assert!(!session_still_live(&db, "oren", &bare).await);
    }

    #[tokio::test]
    async fn live_must_change_flag_gates_token_minted_before_flag() {
        // An admin forcing a password change after login must take effect on the
        // already-issued session immediately. The token was minted WITHOUT the
        // must-change claim, but the live DB flag now gates it (BUG-124).
        async fn ok() -> &'static str {
            "ok"
        }
        let cfg = test_config();
        let db = test_db().await;
        let self_id = db
            .create_user("harry", &hash_password("pw").unwrap(), "examiner")
            .await
            .unwrap();
        // Token minted before the flag is set: claims.must_change == false.
        let (token, _) = cfg.generate_token("harry", "examiner").unwrap();
        // Admin now forces a change on the live account.
        db.set_must_change_password(self_id, true).await.unwrap();

        let app = axum::Router::new()
            .route("/api/v1/cases", axum::routing::get(ok))
            .route("/api/v1/users/:id/password", axum::routing::get(ok))
            .layer(axum::middleware::from_fn_with_state(
                AuthLayerState { config: cfg, db },
                auth_middleware,
            ));

        // A normal endpoint is now gated even though the token predates the flag.
        let resp = tower::ServiceExt::oneshot(app.clone(), get_req("/api/v1/cases", &token))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "live must_change_password must gate a token minted before the flag"
        );

        // The caller's own password endpoint stays reachable so they can rotate.
        let own = format!("/api/v1/users/{}/password", self_id);
        let resp = tower::ServiceExt::oneshot(app, get_req(&own, &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_clearing_cookie_carries_login_attributes() {
        // The logout removal cookie must match the attributes login set so a
        // browser reliably clears the (possibly Secure) auth cookie (BUG-077).
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("{}=sometoken", AUTH_COOKIE_NAME).parse().unwrap(),
        );
        let jar = CookieJar::from_headers(&headers);

        let db = Arc::new(SqliteConnection::new("sqlite::memory:").await.unwrap());
        let resp = logout(State(test_config()), State(db), jar, headers)
            .await
            .into_response();
        let set_cookie: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter(|c| c.contains(AUTH_COOKIE_NAME))
            .collect();
        assert_eq!(
            set_cookie.len(),
            1,
            "expected one auth Set-Cookie: {:?}",
            set_cookie
        );
        let cookie = set_cookie[0];
        assert!(
            cookie.contains("HttpOnly"),
            "logout cookie missing HttpOnly: {}",
            cookie
        );
        assert!(
            cookie.contains("SameSite=Strict"),
            "logout cookie missing SameSite=Strict: {}",
            cookie
        );
        // Removal cookie: empty value + immediate expiry.
        assert!(
            cookie.contains("Max-Age=0"),
            "logout cookie missing Max-Age=0: {}",
            cookie
        );
    }

    #[tokio::test]
    async fn csrf_cookie_is_secure_when_env_enables_it() {
        // On an HTTPS deployment (SEANCE_COOKIE_SECURE=true) the CSRF cookie must
        // carry Secure like the auth cookie, so it is not sent over plain HTTP
        // (BUG-085).
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SEANCE_COOKIE_SECURE", "true");

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                test_config(),
                csrf_middleware,
            ));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        let csrf_cookie = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.contains(CSRF_COOKIE_NAME))
            .map(String::from);
        std::env::remove_var("SEANCE_COOKIE_SECURE");

        let csrf_cookie = csrf_cookie.expect("expected a CSRF Set-Cookie");
        assert!(
            csrf_cookie.contains("Secure"),
            "CSRF cookie must be Secure when SEANCE_COOKIE_SECURE=true: {}",
            csrf_cookie
        );
    }

    #[tokio::test]
    async fn csrf_cookie_not_secure_by_default() {
        // Default (localhost HTTP) must NOT mark the CSRF cookie Secure, else a
        // browser would refuse to send it over http:// and CSRF checks break.
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SEANCE_COOKIE_SECURE");

        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                test_config(),
                csrf_middleware,
            ));
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        let csrf_cookie = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.contains(CSRF_COOKIE_NAME))
            .map(String::from)
            .expect("expected a CSRF Set-Cookie");
        assert!(
            !csrf_cookie.contains("Secure"),
            "CSRF cookie must not be Secure by default: {}",
            csrf_cookie
        );
    }
}
