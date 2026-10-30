#![forbid(unsafe_code)]
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use reqwest::Client;
use serde_json::Value;
mod memory_layer;
mod sweep;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const MAX_HISTORY: usize = 100;

struct App {
    input: String,
    messages: Vec<String>,
    api_url: String,
    active_case_id: Option<String>,
    active_case_name: Option<String>,
    client: Client,
    /// Bearer token from `/login`.
    ///
    /// The REPL is an API client like any other and authenticates like one.
    /// It used to send no credential at all, which meant it worked only against
    /// a server with authentication disabled — an unauthenticated interface
    /// shipping beside an authenticated one, and every action it took was
    /// unattributable in the audit log (BUG-130).
    token: Option<String>,
    scroll_offset: u16,
    should_quit: bool,
    command_history: Vec<String>,
    history_index: Option<usize>,
}

/// How many terminal cells a string occupies.
///
/// Not its byte length, and not its character count: a CJK ideograph is one
/// character that takes two cells, and a combining accent is one character that
/// takes none.
pub(crate) fn display_width(s: &str) -> usize {
    use unicode_width::UnicodeWidthStr;
    s.width()
}

/// Shorten a value for a fixed-width table column, marking that it was
/// shortened.
///
/// A table has to fit the pane, so summary columns really do have to be cut.
/// What they must not do is cut silently: an examiner reading a truncated note
/// with no mark on it has no reason to open the full record. The artifact view
/// wraps rather than cuts, and is where the whole value lives.
pub(crate) fn elide(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let kept: String = value.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
}

impl App {
    fn new(api_url: String) -> App {
        let banner = r#"
         ░▒▓███▓▒
       ░███████████░
      ▒█████████████▒         ░███████░
     ░███████████████        ▒█▓░   ░▓█▒
     ░███▓ ░███  ████        ▒█▓      ░░  ▒██████░   ░██████▒  ▒██▓████▓░   ▒█████▓░   ▓█████▓░
     ░███████████████        ░▓████▒░    ▒█▓░  ░██░ ░▓▓░  ░██░ ▒██░   ▓█▓  ▓█▓   ░██░░██▒   ▒██░
     ░███████████████           ░▒▓████░░██▒▒▒▒▒▒█▓   ░░▒▒▒██▒ ▒██░    ██ ░██        ░██▒▒▒▒▒██░
     ░███████████████        ░░      ░██░██▒▒▒▒▒▒▒░ ░██▓▒▒░▓█▒ ▒██     ██ ░██        ▒█▓▒▒▒▒▒▒▒░
     ░███████████████        ▓█▒░   ░▒█▓ ▒█▓░   ▒▓▒ ▒█▒   ░██░ ▒██     ██  ██▓░  ░██░░██▒   ░▓▓░
     ░███████████████         ▒███████▒░  ▒██████▒  ░▓████▓▓█▒ ▒██░    ██  ░▒██████░  ░▓██████░
     ░█░░████▒████░▒█
          ░░   ░░
"#;
        let mut messages: Vec<String> = banner.lines().map(|s| s.to_string()).collect();
        messages.extend(vec![
            format!("Welcome to Seance REPL v{}", env!("CARGO_PKG_VERSION")),
            format!("Connected to API at {}", api_url),
            "".to_string(),
            "Quick Start:".to_string(),
            "  1. /case list              — view existing cases".to_string(),
            "  2. /case create MyCaseName — create a new case".to_string(),
            "  3. /ingest /path/to/image  — ingest evidence".to_string(),
            "  4. /status                 — monitor processing".to_string(),
            "  5. /search <keyword>       — search artifacts".to_string(),
            "".to_string(),
            "Type /help for all commands, /help <topic> for details.".to_string(),
            "--------------------------------------------------".to_string(),
        ]);

        App {
            input: String::new(),
            messages,
            api_url,
            active_case_id: None,
            active_case_name: None,
            // Bounded, so a server that stops answering — a request parked
            // behind a long export, a socket that went away — returns the
            // prompt with an error instead of holding the REPL for ever. The
            // overall budget matches the server's own 300 s request timeout;
            // the connect budget is short because the server is local.
            client: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap_or_else(|_| Client::new()),
            token: None,
            scroll_offset: 0,
            should_quit: false,
            command_history: Vec::new(),
            history_index: None,
        }
    }

    /// Lay a metadata value out across lines instead of cutting it off.
    ///
    /// # Why this is not a truncation
    ///
    /// This view is the "tell me everything about this artifact" command, and
    /// it used to keep the first eighty characters of each value and discard
    /// the rest — without even an ellipsis, so nothing on screen showed that
    /// anything had been removed.
    ///
    /// The values that matter most here are the ones the parsers write to
    /// qualify a finding, and a qualification comes at the END of a sentence.
    /// A module-list cross-view reads "An independent scan found this structure
    /// and the kernel's module list does not contain it. UNLINKING a module
    /// from that list is the oldest and commonest way of hiding a loaded kernel
    /// module..." and continues, four hundred characters later, "...it is not
    /// by itself proof of any of the three." At eighty characters the examiner
    /// was shown the accusation and none of the doubt.
    ///
    /// Wrapping is therefore not a nicety. Every other tier of this program
    /// takes care not to overstate a finding; cutting the sentence here undoes
    /// that at the last step.
    pub(crate) fn wrap_metadata_value(key: &str, value: &str) -> String {
        /// Wide enough for prose, narrow enough for a split terminal.
        const WIDTH: usize = 76;
        let indent = "      ";
        let first = format!("    {key}: ");

        let mut out = String::new();
        let mut line = first.clone();
        let mut any = false;

        for word in value.split_whitespace() {
            // A word longer than the line gets its own line rather than
            // forcing an over-long one; hashes and paths look like this.
            if line.chars().count() + word.chars().count() + 1 > WIDTH && any {
                out.push_str(line.trim_end());
                out.push('\n');
                line = indent.to_string();
                any = false;
            }
            if any {
                line.push(' ');
            }
            line.push_str(word);
            any = true;
        }
        if !line.trim().is_empty() {
            out.push_str(line.trim_end());
        } else if out.is_empty() {
            out.push_str(first.trim_end());
        }
        out
    }

    fn add_message(&mut self, msg: String) {
        for line in msg.split('\n') {
            self.messages.push(line.to_string());
        }
        self.scroll_offset = 0;
    }

    fn add_table(&mut self, headers: &[&str], rows: &[Vec<String>]) {
        if rows.is_empty() {
            self.add_message("  (no results)".to_string());
            return;
        }
        // Display width, not byte length.
        //
        // `{:width$}` pads a `&str` by how many characters it holds, so widths
        // measured in bytes and padding applied in characters disagree the
        // moment evidence is not ASCII. A Cyrillic message is eighteen bytes
        // and nine characters, so its column was padded to eighteen and every
        // column after it on that row shifted nine places — enough to make a
        // table of Russian or Chinese messages unreadable, on a tool whose
        // whole purpose is reading other people's data.
        //
        // `unicode-width` rather than a character count because a CJK
        // ideograph occupies two terminal cells and a combining accent none.
        let mut widths: Vec<usize> = headers.iter().map(|h| display_width(h)).collect();
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(display_width(cell));
                }
            }
        }
        let header_line: String = headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
            .collect::<Vec<_>>()
            .join(" | ");
        let sep: String = widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("-+-");
        self.add_message(format!("  {}", header_line));
        self.add_message(format!("  {}", sep));
        for row in rows {
            let line: String = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    let w = widths
                        .get(i)
                        .copied()
                        .unwrap_or_else(|| display_width(cell));
                    // Pad by hand: `{:width$}` counts characters, and a CJK
                    // ideograph is one character in two terminal cells.
                    let pad = w.saturating_sub(display_width(cell));
                    format!("{cell}{}", " ".repeat(pad))
                })
                .collect::<Vec<_>>()
                .join(" | ");
            self.add_message(format!("  {}", line));
        }
    }

    fn require_case(&self) -> Option<String> {
        self.active_case_id.clone()
    }

    fn no_case_msg(&mut self) {
        self.add_message("No active case. Use /case list and /case switch <id>.".to_string());
    }

    /// Attach the bearer token, when logged in.
    ///
    /// Every request goes through here rather than each call site remembering:
    /// a request that forgot would fail closed against an authenticated server,
    /// but against one with auth disabled it would silently succeed, and the
    /// omission would only surface in a deployment where it mattered.
    fn authed(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(token) => builder.bearer_auth(token),
            None => builder,
        }
    }

    /// Exchange credentials for a token via the ordinary login endpoint.
    ///
    /// Deliberately the same endpoint the web UI uses, rather than minting a
    /// token in-process because the REPL happens to share an address space with
    /// the server. Going through the front door means the login is rate-limited,
    /// audited and attributed like any other — which is the point of having an
    /// audit log at all.
    async fn login(&mut self, username: &str, password: &str) -> std::result::Result<(), String> {
        let url = format!("{}/api/v1/auth/login", self.api_url);
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "username": username, "password": password }))
            .send()
            .await
            .map_err(|e| format!("Connection failed: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            // The body may carry a rate-limit or lockout reason worth showing;
            // it is the server's own words, not this client's guess.
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Login failed ({status}): {body}"));
        }
        let payload: Value = response
            .json()
            .await
            .map_err(|e| format!("Login response did not parse: {e}"))?;
        let token = payload
            .get("token")
            .and_then(|v| v.as_str())
            .ok_or("Login succeeded but the response carried no token")?;
        self.token = Some(token.to_string());
        if payload
            .get("must_change_password")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Err(
                "This account must change its password before it can be used. Do that in the \
                 web UI, then log in here again."
                    .to_string(),
            );
        }
        Ok(())
    }

    /// `/login <username> <password>`.
    ///
    /// The password is taken on the command line rather than prompted for,
    /// because this REPL renders through a full-screen terminal UI that has no
    /// masked-input mode. That is a real exposure — the password lands in the
    /// command history — so the history entry is redacted immediately, and the
    /// help text says to prefer the web UI on a shared machine.
    async fn handle_login(&mut self, parts: &[&str]) {
        if parts.len() < 3 {
            self.add_message("Usage: /login <username> <password>".to_string());
            self.add_message(
                "The password appears on screen as you type it. On a shared or recorded \
                 terminal, log in through the web UI instead."
                    .to_string(),
            );
            return;
        }
        let (username, password) = (parts[1], parts[2]);
        match self.login(username, password).await {
            Ok(()) => self.add_message(format!(
                "Logged in as {username}. Subsequent commands carry this session, and the \
                 audit log attributes them to it."
            )),
            Err(why) => self.add_message(why),
        }
        // Whatever the outcome, the password must not sit in the scrollback or
        // the recallable history.
        if let Some(last) = self.command_history.last_mut() {
            if last.starts_with("/login") {
                *last = format!("/login {username} ********");
            }
        }
        for line in self.messages.iter_mut() {
            if line.starts_with("/login ") || line.contains("> /login ") {
                *line = format!("/login {username} ********");
            }
        }
    }

    /// `/unlock <artifact_id> <kind> <secret>` — `POST …/credential`
    /// (HUNT-120).
    ///
    /// Everything after the kind is the secret, spaces included, so a LUKS
    /// passphrase of several words is one secret. As with `/login`, this UI has
    /// no masked-input mode, so the secret appears on screen as it is typed;
    /// the history entry and the scrollback line are redacted immediately,
    /// whatever the outcome, and the usage text says to prefer the web UI's
    /// Needs attention field on a shared or recorded terminal.
    ///
    /// `/unlock --read <artifact_id> <kind> <secret>` is `POST …/unlock`
    /// (HUNT-254, BUG-026): unlock for reading, the key held in the server's
    /// memory for this case with a time limit; `/unlock --lock <artifact_id>`
    /// is `DELETE …/unlock`. The `--read` secret is redacted the same way.
    async fn handle_unlock(&mut self, command: &str) {
        let mode = unlock_mode(command);
        // Redact first, before anything can return early.
        let redacted = match &mode {
            Some(UnlockMode::Run(artifact, kind, _)) => {
                format!("/unlock {artifact} {kind} ********")
            }
            Some(UnlockMode::Read(artifact, kind, _)) => {
                format!("/unlock --read {artifact} {kind} ********")
            }
            Some(UnlockMode::Lock(artifact)) => format!("/unlock --lock {artifact}"),
            None => "/unlock ********".to_string(),
        };
        if let Some(last) = self.command_history.last_mut() {
            if last.starts_with("/unlock") {
                *last = redacted.clone();
            }
        }
        for line in self.messages.iter_mut() {
            if line.starts_with("/unlock ") || line.contains("> /unlock ") {
                *line = format!("> {redacted}");
            }
        }
        let args = match mode {
            Some(UnlockMode::Run(a, k, s)) => Some((a, k, s)),
            Some(UnlockMode::Read(artifact, kind, secret)) => {
                self.handle_unlock_for_reading(artifact, kind, secret).await;
                return;
            }
            Some(UnlockMode::Lock(artifact)) => {
                self.handle_lock_for_reading(artifact).await;
                return;
            }
            None => None,
        };
        let Some((artifact, kind, secret)) = args else {
            self.add_message("Usage: /unlock <artifact_id> <kind> <secret>".to_string());
            self.add_message(format!("  kinds: {}", UNLOCK_KINDS.join(", ")));
            self.add_message(
                "   or: /unlock --read <artifact_id> <kind> <secret>   (unlock for reading)"
                    .to_string(),
            );
            self.add_message(format!("       kinds: {}", UNLOCK_READ_KINDS.join(", ")));
            self.add_message("   or: /unlock --lock <artifact_id>   (lock again)".to_string());
            self.add_message(
                "  The secret is everything after the one space that follows the kind, taken \
                 as typed: leading and trailing spaces are part of it."
                    .to_string(),
            );
            self.add_message(
                "The secret appears on screen as you type it. On a shared or recorded \
                 terminal, supply it from the web UI's Needs attention queue instead."
                    .to_string(),
            );
            return;
        };
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!(
            "{}/api/v1/cases/{}/artifacts/{}/credential",
            self.api_url, case_id, artifact
        );
        let body = serde_json::json!({ "kind": kind, "secret": secret });
        match self.api_post(&url, &body).await {
            Ok(resp) => {
                let job_id = resp["job_id"].as_str().unwrap_or("?");
                let status = resp["status"].as_str().unwrap_or("?");
                let module = resp["module_id"].as_str().unwrap_or("?");
                self.add_message(format!(
                    "{kind} supplied for {artifact}: {module} job {job_id} ({status}). Watch it \
                     with /module job {job_id} — a wrong secret fails the job and changes \
                     nothing; the secret is not kept."
                ));
            }
            Err(e) => self.add_message(e),
        }
    }

    /// `/unlock --read`: `POST …/unlock` (BUG-026, HUNT-254).
    async fn handle_unlock_for_reading(&mut self, artifact: &str, kind: &str, secret: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!(
            "{}/api/v1/cases/{}/artifacts/{}/unlock",
            self.api_url, case_id, artifact
        );
        let body = serde_json::json!({ "kind": kind, "secret": secret });
        match self.api_post(&url, &body).await {
            Ok(resp) => {
                let secs = resp["expires_in_secs"].as_u64().unwrap_or(0);
                self.add_message(format!(
                    "Unlocked for reading with {kind}: {artifact} and what is beneath it read \
                     as plaintext in this case for {:.1} h, or until /unlock --lock {artifact}, \
                     the case is deleted or the server restarts. The secret is not kept.",
                    secs as f64 / 3600.0
                ));
            }
            Err(e) => self.add_message(e),
        }
    }

    /// `/unlock --lock`: `DELETE …/unlock`.
    async fn handle_lock_for_reading(&mut self, artifact: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!(
            "{}/api/v1/cases/{}/artifacts/{}/unlock",
            self.api_url, case_id, artifact
        );
        match self.api_delete(&url).await {
            Ok(_) => self.add_message(format!(
                "Locked again: {artifact}'s keys are forgotten (if any were held)."
            )),
            Err(e) => self.add_message(e),
        }
    }

    async fn api_get(&self, url: &str) -> std::result::Result<Value, String> {
        match self.authed(self.client.get(url)).send().await {
            Ok(res) => {
                let status = res.status();
                if status.is_success() {
                    res.json::<Value>()
                        .await
                        .map_err(|e| format!("Parse error: {}", e))
                } else if status == reqwest::StatusCode::UNAUTHORIZED {
                    // Without this the REPL reported a bare 401 and an operator
                    // had no way to know the interface could authenticate at
                    // all — it never could, before.
                    Err("Not authenticated: run /login <username> <password> first.".to_string())
                } else {
                    let body = res.text().await.unwrap_or_default();
                    Err(format!("API Error {}: {}", status, body))
                }
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    async fn api_post(&self, url: &str, body: &Value) -> std::result::Result<Value, String> {
        match self.authed(self.client.post(url)).json(body).send().await {
            Ok(res) => {
                let status = res.status();
                if status.is_success() {
                    res.json::<Value>()
                        .await
                        .map_err(|e| format!("Parse error: {}", e))
                } else if status == reqwest::StatusCode::UNAUTHORIZED {
                    // Without this the REPL reported a bare 401 and an operator
                    // had no way to know the interface could authenticate at
                    // all — it never could, before.
                    Err("Not authenticated: run /login <username> <password> first.".to_string())
                } else {
                    let body = res.text().await.unwrap_or_default();
                    Err(format!("API Error {}: {}", status, body))
                }
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    async fn api_put(&self, url: &str, body: &Value) -> std::result::Result<Value, String> {
        match self.authed(self.client.put(url)).json(body).send().await {
            Ok(res) => {
                let status = res.status();
                if status.is_success() {
                    res.json::<Value>()
                        .await
                        .map_err(|e| format!("Parse error: {}", e))
                } else if status == reqwest::StatusCode::UNAUTHORIZED {
                    // Without this the REPL reported a bare 401 and an operator
                    // had no way to know the interface could authenticate at
                    // all — it never could, before.
                    Err("Not authenticated: run /login <username> <password> first.".to_string())
                } else {
                    let body = res.text().await.unwrap_or_default();
                    Err(format!("API Error {}: {}", status, body))
                }
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    async fn api_delete(&self, url: &str) -> std::result::Result<u16, String> {
        match self.authed(self.client.delete(url)).send().await {
            Ok(res) => {
                let status = res.status().as_u16();
                if res.status().is_success() {
                    Ok(status)
                } else if status == reqwest::StatusCode::UNAUTHORIZED {
                    // Without this the REPL reported a bare 401 and an operator
                    // had no way to know the interface could authenticate at
                    // all — it never could, before.
                    Err("Not authenticated: run /login <username> <password> first.".to_string())
                } else {
                    let body = res.text().await.unwrap_or_default();
                    Err(format!("API Error {}: {}", status, body))
                }
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    async fn execute_command(&mut self) {
        // `/unlock` reads its secret from the line as typed: trimming the
        // whole line would strip a password's trailing spaces.
        let raw_unlock = self
            .input
            .trim_start()
            .starts_with("/unlock")
            .then(|| self.input.trim_start().to_string());
        let command = self.input.trim().to_string();
        self.input.clear();
        self.history_index = None;
        self.add_message(format!("> {}", command));

        if command.is_empty() {
            return;
        }

        // Save to history
        if self.command_history.last().map(|s| s.as_str()) != Some(&command) {
            self.command_history.push(command.clone());
            if self.command_history.len() > MAX_HISTORY {
                self.command_history.remove(0);
            }
        }

        let parts: Vec<&str> = command.split_whitespace().collect();
        match parts[0] {
            "/quit" | "/exit" => self.should_quit = true,
            "/clear" => self.messages.clear(),
            "/help" => self.show_help(&parts),
            "/case" => self.handle_case(&parts, &command).await,
            "/ingest" => {
                if parts.len() < 2 {
                    self.add_message("Usage: /ingest <path>".to_string());
                } else {
                    let path = command.trim_start_matches("/ingest ").trim();
                    self.handle_ingest(path).await;
                }
            }
            "/search" => {
                if parts.len() < 2 {
                    self.add_message(
                        "Usage: /search <query> [--regex] [--type <type>] [--ext <ext>]"
                            .to_string(),
                    );
                } else {
                    self.handle_search(&command).await;
                }
            }
            "/sweep" => self.handle_sweep(&command).await,
            "/timeline" => self.handle_timeline(&parts).await,
            "/stats" => self.handle_stats().await,
            "/duplicates" => self.handle_duplicates(&parts).await,
            "/artifact" => self.handle_artifact(&parts).await,
            "/hex" => self.handle_hex(&parts).await,
            "/bookmark" => self.handle_bookmark(&parts, &command).await,
            "/module" => self.handle_module(&parts, &command).await,
            "/hashset" => self.handle_hashset(&parts, &command).await,
            "/profile" => self.handle_profile(&parts, &command).await,
            "/audit" => self.handle_audit(&parts).await,
            "/filter" => self.handle_filter(&parts, &command).await,
            "/export" => self.handle_export(&parts).await,
            "/memory" => self.handle_memory(&parts).await,
            "/status" => self.handle_status().await,
            "/verify" => self.handle_verify(&parts).await,
            "/browse" => self.handle_browse(&parts, &command).await,
            "/login" => self.handle_login(&parts).await,
            "/unlock" => {
                let line = raw_unlock.as_deref().unwrap_or(&command);
                self.handle_unlock(line).await
            }
            "/logout" => {
                self.token = None;
                self.add_message(
                    "Logged out. The token is discarded from memory; the server session \
                     expires on its own schedule."
                        .to_string(),
                );
            }
            _ => {
                let known = KNOWN_COMMANDS;
                let suggestion = known
                    .iter()
                    .filter_map(|cmd| {
                        let dist = levenshtein(parts[0], cmd);
                        if dist <= 2 {
                            Some((*cmd, dist))
                        } else {
                            None
                        }
                    })
                    .min_by_key(|(_, d)| *d)
                    .map(|(cmd, _)| cmd);
                if let Some(cmd) = suggestion {
                    self.add_message(format!(
                        "Unknown command: {}. Did you mean {}?",
                        parts[0], cmd
                    ));
                } else {
                    self.add_message(format!(
                        "Unknown command: {}. Type /help for available commands.",
                        parts[0]
                    ));
                }
            }
        }
    }

    fn show_help(&mut self, parts: &[&str]) {
        if parts.len() > 1 {
            match parts[1] {
                "case" => {
                    self.add_message("Case Management:".to_string());
                    self.add_message("  /case list                       - List all cases".to_string());
                    self.add_message("  /case create <name> [ref]        - Create a new case".to_string());
                    self.add_message("  /case switch <id>                - Switch active case".to_string());
                    self.add_message("  /case info                       - Show active case details".to_string());
                    self.add_message("  /case update <field> <value>     - Update case field (name/ref/examiner)".to_string());
                    self.add_message("  /case delete                     - Delete active case".to_string());
                }
                "artifact" => {
                    self.add_message("Artifact Commands:".to_string());
                    self.add_message("  /artifact <id>                   - Show artifact metadata".to_string());
                    self.add_message("  /artifact children <id>          - List child artifacts".to_string());
                    self.add_message("  /artifact tree                   - Show analysis tree".to_string());
                    self.add_message("  /artifact recent                 - Show recent artifacts".to_string());
                    self.add_message("  /artifact history <id>           - Show processing history".to_string());
                    self.add_message("  /artifact delete <id>            - Delete artifact".to_string());
                }
                "search" => {
                    self.add_message("Search:".to_string());
                    for line in SEARCH_HELP {
                        self.add_message(line.to_string());
                    }
                }
                "bookmark" => {
                    self.add_message("Bookmarks:".to_string());
                    self.add_message("  /bookmark list [category_id]     - List bookmarks".to_string());
                    self.add_message("  /bookmark add <artifact_id> [note] - Add bookmark".to_string());
                    self.add_message("  /bookmark remove <artifact_id>   - Remove bookmark".to_string());
                    self.add_message("  /bookmark categories             - List categories".to_string());
                    self.add_message("  /bookmark addcat <name> [color]  - Create category".to_string());
                }
                "module" => {
                    self.add_message("Modules:".to_string());
                    self.add_message("  /module list [--type <type>]     - List available modules".to_string());
                    self.add_message("  /module run <module_id> <artifact_id> - Run module".to_string());
                    self.add_message("  /module jobs                     - List ad-hoc jobs".to_string());
                    self.add_message("  /module job <job_id>             - Get job details".to_string());
                    self.add_message("  /unlock <artifact_id> <kind> <secret> - Re-run the decryptor on one locked artifact with a secret".to_string());
                    self.add_message(format!("      kinds: {}", UNLOCK_KINDS.join(", ")));
                    self.add_message("  /unlock --read <artifact_id> <kind> <secret> - Unlock for reading: the key held in server memory for this case, with a time limit".to_string());
                    self.add_message(format!("      kinds: {}", UNLOCK_READ_KINDS.join(", ")));
                    self.add_message("  /unlock --lock <artifact_id>     - Lock again: forget the key".to_string());
                }
                "timeline" => {
                    self.add_message("Timeline:".to_string());
                    self.add_message("  /timeline [limit]                - Show timeline events (default 20)".to_string());
                    self.add_message("  /timeline 50 --modules mft       - Filter by source module".to_string());
                    self.add_message("  /timeline --search login         - Search within timeline".to_string());
                }
                "export" => {
                    self.add_message("Export:".to_string());
                    self.add_message("  /export timeline [csv|json|pdf]  - Export timeline".to_string());
                    self.add_message("  /export timeline body            - Export the case's files as a mactime body file".to_string());
                    self.add_message("  /export bookmarks [csv|json]     - Export bookmarks".to_string());
                    self.add_message("  /export report [pdf|html|xlsx|docx|rtf|xml] - Export full report (default pdf)".to_string());
                    self.add_message("  /export audit                    - Export audit log as CSV".to_string());
                }
                "hashset" => {
                    self.add_message("Hash Sets:".to_string());
                    self.add_message("  /hashset list                    - List hash sets".to_string());
                    self.add_message("  /hashset create <name> [type] [algo] - Create (type: known/notable, algo: md5/sha1/sha256)".to_string());
                    self.add_message("  /hashset delete <id>             - Delete hash set".to_string());
                    self.add_message("  /hashset check <artifact_id>     - Check artifact against hash sets".to_string());
                }
                "filter" => {
                    self.add_message("Filters:".to_string());
                    self.add_message("  /filter list                     - List saved filters".to_string());
                    self.add_message("  /filter create <name> <json>     - Create filter".to_string());
                    self.add_message("  /filter get <id>                 - View filter details".to_string());
                    self.add_message("  /filter apply <id>               - Apply filter, show matching artifacts".to_string());
                    self.add_message("  /filter delete <id>              - Delete filter".to_string());
                }
                "duplicates" => {
                    self.add_message("Duplicates:".to_string());
                    self.add_message("  /duplicates                      - Exact (SHA-256) duplicate groups".to_string());
                    self.add_message("  /duplicates near [threshold]     - PDQ near-duplicate image groups (default 31 bits)".to_string());
                }
                _ => self.add_message(format!("No detailed help for '{}'. Topics: case, artifact, search, bookmark, module, timeline, export, hashset, filter, duplicates", parts[1])),
            }
            return;
        }

        self.add_message("Available Commands:".to_string());
        self.add_message("".to_string());
        self.add_message("  Case Management:".to_string());
        self.add_message("    /case list|create|switch|info|update|delete".to_string());
        self.add_message("".to_string());
        self.add_message("  Evidence & Analysis:".to_string());
        self.add_message(
            "    /ingest <path>                 - Ingest evidence file/image".to_string(),
        );
        self.add_message("    /artifact <id>                 - View artifact details".to_string());
        self.add_message("    /artifact children|tree|recent|history|delete".to_string());
        self.add_message(
            "    /hex <artifact_id> [offset] [len] - Hex dump of artifact".to_string(),
        );
        self.add_message(
            "    /verify <artifact_id>          - Verify artifact integrity".to_string(),
        );
        self.add_message(
            "    /memory layer <image_id> [--start a] [--end a] - Save a memory image's physical layer + hole manifest"
                .to_string(),
        );
        self.add_message("".to_string());
        self.add_message("  Search & Timeline:".to_string());
        self.add_message("    /search <query> [--regex] [--type t] [--ext .x]".to_string());
        self.add_message("    /timeline [limit] [--modules m] [--search s]".to_string());
        self.add_message("    /stats                         - Case statistics".to_string());
        self.add_message("".to_string());
        self.add_message("  Organization:".to_string());
        self.add_message("    /bookmark list|add|remove|categories|addcat".to_string());
        self.add_message("    /filter list|create|get|apply|delete".to_string());
        self.add_message("".to_string());
        self.add_message("  Modules & Processing:".to_string());
        self.add_message("    /module list|run|jobs|job".to_string());
        self.add_message(
            "    /unlock <artifact_id> <kind> <secret> - Supply a secret for one locked artifact"
                .to_string(),
        );
        self.add_message(
            "    /unlock --read|--lock ...  - Unlock an encrypted backup or volume for reading, or lock it again"
                .to_string(),
        );
        self.add_message("    /hashset list|create|import|delete|check".to_string());
        self.add_message("    /profile list|create|activate|delete".to_string());
        self.add_message("".to_string());
        self.add_message("  Reporting & System:".to_string());
        self.add_message("    /audit [limit]                 - View audit log".to_string());
        self.add_message("    /export timeline|bookmarks|report|audit".to_string());
        self.add_message("    /status                        - Processing status".to_string());
        self.add_message(
            "    /browse [path]                 - Browse local filesystem".to_string(),
        );
        self.add_message("".to_string());
        self.add_message("  General:".to_string());
        self.add_message("    /clear                         - Clear screen".to_string());
        self.add_message("    /help [topic]                  - Show help (case, artifact, search, bookmark, module, timeline, export, hashset, filter)".to_string());
        self.add_message("    /quit                          - Exit REPL".to_string());
        self.add_message("".to_string());
        self.add_message(
            "  Navigation: Up/Down=history, PgUp/PgDn=scroll output, Esc=clear input".to_string(),
        );
        self.add_message("".to_string());
        self.add_message("  Examples:".to_string());
        self.add_message("    /case create Investigation-001 REF-2024-001".to_string());
        self.add_message("    /ingest /evidence/disk.E01".to_string());
        self.add_message("    /search password --type FileContent".to_string());
        self.add_message("    /timeline 50 --search login".to_string());
        self.add_message("    /bookmark add <id> Suspicious file found".to_string());
        self.add_message("    /export report pdf".to_string());
    }

    // ---- Case Management ----

    async fn handle_case(&mut self, parts: &[&str], command: &str) {
        if parts.len() < 2 {
            self.add_message("Usage: /case <list|create|switch|info|update|delete>".to_string());
            return;
        }
        match parts[1] {
            "list" => self.handle_case_list().await,
            "create" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /case create <name> [reference]".to_string());
                } else {
                    let name = parts[2];
                    let reference = if parts.len() > 3 {
                        Some(parts[3])
                    } else {
                        None
                    };
                    self.handle_case_create(name, reference).await;
                }
            }
            "switch" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /case switch <id>".to_string());
                } else {
                    self.handle_case_switch(parts[2]).await;
                }
            }
            "info" => self.handle_case_info().await,
            "update" => {
                if parts.len() < 4 {
                    self.add_message("Usage: /case update <name|ref|examiner> <value>".to_string());
                } else {
                    let value = command.splitn(4, ' ').nth(3).unwrap_or("");
                    self.handle_case_update(parts[2], value).await;
                }
            }
            "delete" => self.handle_case_delete().await,
            _ => self.add_message(
                "Unknown case command. Use: list, create, switch, info, update, delete".to_string(),
            ),
        }
    }

    async fn handle_case_list(&mut self) {
        let url = format!("{}/api/v1/cases", self.api_url);
        match self.api_get(&url).await {
            Ok(val) => {
                if let Some(cases) = val.as_array() {
                    if cases.is_empty() {
                        self.add_message("No cases found.".to_string());
                        return;
                    }
                    let rows: Vec<Vec<String>> = cases
                        .iter()
                        .map(|c| {
                            vec![
                                c["id"].as_str().unwrap_or("?").to_string(),
                                c["name"].as_str().unwrap_or("?").to_string(),
                                c["status"].as_str().unwrap_or("?").to_string(),
                                c["examiner_name"].as_str().unwrap_or("").to_string(),
                            ]
                        })
                        .collect();
                    self.add_message("Cases:".to_string());
                    self.add_table(&["ID", "Name", "Status", "Examiner"], &rows);
                }
            }
            Err(e) => self.add_message(e),
        }
    }

    async fn handle_case_create(&mut self, name: &str, reference: Option<&str>) {
        let url = format!("{}/api/v1/cases", self.api_url);
        let body = serde_json::json!({
            "name": name,
            "reference_number": reference,
            "examiner_name": "REPL User"
        });
        match self.api_post(&url, &body).await {
            Ok(case) => {
                let id = case["id"].as_str().unwrap_or("?");
                let name = case["name"].as_str().unwrap_or("?");
                self.add_message(format!("Created case: {} ({})", name, id));
                self.active_case_id = Some(id.to_string());
                self.active_case_name = Some(name.to_string());
            }
            Err(e) => self.add_message(e),
        }
    }

    async fn handle_case_switch(&mut self, id: &str) {
        // Pre-flight: validate UUID format
        if uuid::Uuid::parse_str(id).is_err() {
            self.add_message(format!(
                "Error: '{}' is not a valid case ID (expected UUID format).",
                id
            ));
            self.add_message("Use /case list to see valid case IDs.".to_string());
            return;
        }
        let url = format!("{}/api/v1/cases/{}", self.api_url, id);
        match self.api_get(&url).await {
            Ok(case) => {
                let name = case["name"].as_str().unwrap_or("?");
                self.active_case_id = Some(id.to_string());
                self.active_case_name = Some(name.to_string());
                self.add_message(format!("Switched to case: {} ({})", name, id));
            }
            Err(e) => self.add_message(e),
        }
    }

    async fn handle_case_info(&mut self) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!("{}/api/v1/cases/{}", self.api_url, case_id);
        match self.api_get(&url).await {
            Ok(case) => {
                self.add_message("Case Details:".to_string());
                self.add_message(format!(
                    "  ID:        {}",
                    case["id"].as_str().unwrap_or("?")
                ));
                self.add_message(format!(
                    "  Name:      {}",
                    case["name"].as_str().unwrap_or("?")
                ));
                self.add_message(format!(
                    "  Status:    {}",
                    case["status"].as_str().unwrap_or("?")
                ));
                self.add_message(format!(
                    "  Reference: {}",
                    case["reference_number"].as_str().unwrap_or("")
                ));
                self.add_message(format!(
                    "  Examiner:  {}",
                    case["examiner_name"].as_str().unwrap_or("")
                ));
                self.add_message(format!(
                    "  Created:   {}",
                    case["created_at"].as_str().unwrap_or("?")
                ));
                self.add_message(format!(
                    "  Updated:   {}",
                    case["updated_at"].as_str().unwrap_or("?")
                ));
            }
            Err(e) => self.add_message(e),
        }
    }

    async fn handle_case_update(&mut self, field: &str, value: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!("{}/api/v1/cases/{}", self.api_url, case_id);
        let body = match field {
            "name" => serde_json::json!({"name": value}),
            "ref" | "reference" => serde_json::json!({"reference_number": value}),
            "examiner" => serde_json::json!({"examiner_name": value}),
            _ => {
                self.add_message("Unknown field. Use: name, ref, examiner".to_string());
                return;
            }
        };
        match self.api_put(&url, &body).await {
            Ok(case) => {
                let name = case["name"].as_str().unwrap_or("?");
                self.active_case_name = Some(name.to_string());
                self.add_message(format!("Case updated: {}", name));
            }
            Err(e) => self.add_message(e),
        }
    }

    async fn handle_case_delete(&mut self) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!("{}/api/v1/cases/{}", self.api_url, case_id);
        match self.api_delete(&url).await {
            Ok(_) => {
                self.add_message(format!("Case {} deleted.", case_id));
                self.active_case_id = None;
                self.active_case_name = None;
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Ingestion ----

    async fn handle_ingest(&mut self, path: &str) {
        // Pre-flight: check file exists before sending to API
        if !std::path::Path::new(path).exists() {
            self.add_message(format!("Error: path does not exist: {}", path));
            self.add_message("Tip: use an absolute path, e.g. /home/user/evidence.e01".to_string());
            return;
        }
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!("{}/api/v1/cases/{}/ingest", self.api_url, case_id);
        let body = serde_json::json!({"path": path});
        match self.api_post(&url, &body).await {
            Ok(resp) => {
                let status = resp["status"].as_str().unwrap_or("unknown");
                let artifact_id = resp["artifact_id"].as_str().unwrap_or("?");
                self.add_message(format!("Ingestion {}: artifact_id={}", status, artifact_id));
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Search ----

    /// `/sweep`: the case-wide byte sweep (ROADMAP §1.2). The body and the
    /// printout are the pure `sweep::sweep_request_body` and
    /// `sweep::format_sweep_response`.
    async fn handle_sweep(&mut self, command: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let body = match sweep::sweep_request_body(command) {
            Ok(body) => body,
            Err(e) => {
                self.add_message(e);
                return;
            }
        };
        let url = format!("{}/api/v1/cases/{}/search/sweep", self.api_url, case_id);
        match self.api_post(&url, &body).await {
            Ok(resp) => {
                for line in sweep::format_sweep_response(&resp) {
                    self.add_message(line);
                }
            }
            Err(e) => self.add_message(format!("Sweep refused or failed: {e}")),
        }
    }

    async fn handle_search(&mut self, command: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };

        // Parse flags from command
        let after_search = command.trim_start_matches("/search ").trim();
        let mut query_parts = Vec::new();
        let mut use_regex = false;
        let mut type_filter = None;
        let mut ext_filter = None;
        let words: Vec<&str> = after_search.split_whitespace().collect();
        let mut i = 0;
        while i < words.len() {
            match words[i] {
                "--regex" => use_regex = true,
                "--type" => {
                    if i + 1 < words.len() {
                        type_filter = Some(words[i + 1]);
                        i += 1;
                    }
                }
                "--ext" => {
                    if i + 1 < words.len() {
                        ext_filter = Some(words[i + 1]);
                        i += 1;
                    }
                }
                _ => query_parts.push(words[i]),
            }
            i += 1;
        }
        let query = query_parts.join(" ");
        let mut url = format!(
            "{}/api/v1/cases/{}/search?q={}",
            self.api_url,
            case_id,
            urlencoding::encode(&query)
        );
        if use_regex {
            url.push_str("&regex=true");
        }
        if let Some(t) = type_filter {
            url.push_str(&format!("&types={}", t));
        }
        if let Some(e) = ext_filter {
            url.push_str(&format!("&extensions={}", e));
        }

        match self.api_get(&url).await {
            Ok(resp) => {
                let results = resp["results"].as_array().or_else(|| resp.as_array());
                if let Some(results) = results {
                    let total = resp["total_count"].as_u64().unwrap_or(results.len() as u64);
                    let elapsed = resp["elapsed_ms"].as_u64().unwrap_or(0);
                    // Say how many are being shown as well as how many exist:
                    // "Found 900 results" above twenty rows reads as though the
                    // rest are somewhere further down the pane.
                    const SHOWN: usize = 20;
                    if total as usize > SHOWN {
                        self.add_message(format!(
                            "Found {} results ({} ms), showing the first {}:",
                            total, elapsed, SHOWN
                        ));
                    } else {
                        self.add_message(format!("Found {} results ({} ms):", total, elapsed));
                    }
                    for (i, result) in results.iter().take(SHOWN).enumerate() {
                        let score = result["score"].as_f64().unwrap_or(0.0);
                        let name = result["artifact_name"]
                            .as_str()
                            .or_else(|| result["name"].as_str())
                            .unwrap_or("?");
                        let snippet = result["highlighted_content"]
                            .as_str()
                            .or_else(|| result["snippet"].as_str())
                            .unwrap_or("");
                        let id = result["artifact_id"].as_str().unwrap_or("");
                        self.add_message(format!("  {}. [{:.2}] {} ({})", i + 1, score, name, id));
                        if !snippet.is_empty() {
                            self.add_message(format!("     {}", snippet));
                        }
                    }
                    if total > 20 {
                        self.add_message(format!("  ... showing 20 of {}", total));
                    }
                    for line in search_scope_lines(&resp, total) {
                        self.add_message(line);
                    }
                } else {
                    self.add_message("No results found.".to_string());
                }
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Timeline ----

    async fn handle_timeline(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };

        let mut page_size = 20;
        let mut modules = None;
        let mut search = None;
        let mut i = 1;
        while i < parts.len() {
            match parts[i] {
                "--modules" | "-m" => {
                    if i + 1 < parts.len() {
                        modules = Some(parts[i + 1]);
                        i += 1;
                    }
                }
                "--search" | "-s" => {
                    if i + 1 < parts.len() {
                        search = Some(parts[i + 1]);
                        i += 1;
                    }
                }
                other => {
                    if let Ok(n) = other.parse::<i64>() {
                        page_size = n;
                    }
                }
            }
            i += 1;
        }

        let mut url = format!(
            "{}/api/v1/cases/{}/timeline?page_size={}",
            self.api_url, case_id, page_size
        );
        if let Some(m) = modules {
            url.push_str(&format!("&modules={}", m));
        }
        if let Some(s) = search {
            url.push_str(&format!("&search={}", urlencoding::encode(s)));
        }

        match self.api_get(&url).await {
            Ok(resp) => {
                let events = resp["events"].as_array();
                let total = resp["total"].as_u64().unwrap_or(0);
                if let Some(events) = events {
                    self.add_message(format!(
                        "Timeline ({} events, {} total):",
                        events.len(),
                        total
                    ));
                    let rows: Vec<Vec<String>> = events
                        .iter()
                        .map(|e| {
                            vec![
                                e["timestamp"].as_str().unwrap_or("?").to_string(),
                                e["timestamp_desc"].as_str().unwrap_or("").to_string(),
                                elide(e["short_desc"].as_str().unwrap_or(""), 60),
                                e["source_module"].as_str().unwrap_or("").to_string(),
                            ]
                        })
                        .collect();
                    self.add_table(&["Timestamp", "Type", "Description", "Source"], &rows);
                } else {
                    self.add_message("No timeline events.".to_string());
                }
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Stats ----

    async fn handle_stats(&mut self) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let url = format!("{}/api/v1/cases/{}/stats", self.api_url, case_id);
        match self.api_get(&url).await {
            Ok(stats) => {
                self.add_message("Case Statistics:".to_string());
                self.add_message(format!("  Total Artifacts: {}", stats["total_artifacts"]));
                if let Some(counts) = stats["artifact_counts_by_type"].as_object() {
                    for (typ, count) in counts {
                        self.add_message(format!("    {}: {}", typ, count));
                    }
                }
            }
            Err(e) => self.add_message(e),
        }
    }

    /// `/duplicates` — exact (SHA-256) duplicate groups.
    /// `/duplicates near [threshold]` — PDQ near-duplicate image groups.
    async fn handle_duplicates(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let near = parts.get(1).map(|s| *s == "near").unwrap_or(false);
        if near {
            let threshold = parts
                .get(2)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(31);
            let url = format!(
                "{}/api/v1/cases/{}/near_duplicate_images?threshold={}",
                self.api_url, case_id, threshold
            );
            match self.api_get(&url).await {
                Ok(val) => {
                    let scanned = val["images_scanned"].as_u64().unwrap_or(0);
                    let count = val["group_count"].as_u64().unwrap_or(0);
                    self.add_message(format!(
                        "Near-duplicate image groups (PDQ ≤ {threshold} bits): {count} \
                         (scanned {scanned} images). A lead for review, not an identification."
                    ));
                    if let Some(groups) = val["groups"].as_array() {
                        let rows: Vec<Vec<String>> = groups
                            .iter()
                            .enumerate()
                            .map(|(i, g)| {
                                // Map EVERY member, not just those with an image
                                // lineage: a member whose parent_id is null must
                                // still be listed (by its record id) or the row's
                                // Count would exceed the IDs shown, hiding a member
                                // of the duplicate group from the examiner.
                                let ids: Vec<String> = g["members"]
                                    .as_array()
                                    .map(|m| {
                                        m.iter()
                                            .map(|x| match x["image_artifact_id"].as_str() {
                                                Some(id) => id.to_string(),
                                                None => format!(
                                                    "(no image; record {})",
                                                    x["record_id"].as_str().unwrap_or("?")
                                                ),
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                vec![format!("{}", i + 1), g["count"].to_string(), ids.join(", ")]
                            })
                            .collect();
                        if !rows.is_empty() {
                            self.add_table(&["Group", "Count", "Image artifact IDs"], &rows);
                        }
                    }
                }
                Err(e) => self.add_message(e),
            }
        } else {
            let url = format!("{}/api/v1/cases/{}/duplicates", self.api_url, case_id);
            match self.api_get(&url).await {
                Ok(val) => {
                    self.add_message(format!(
                        "Exact-duplicate groups: {} ({} redundant copies). \
                         Use `/duplicates near` for perceptual near-duplicates.",
                        val["group_count"], val["redundant_copies"]
                    ));
                }
                Err(e) => self.add_message(e),
            }
        }
    }

    // ---- Artifact Commands ----

    async fn handle_artifact(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message("Usage: /artifact <id> | children <id> | tree | recent | history <id> | delete <id>".to_string());
            return;
        }
        match parts[1] {
            "tree" => {
                let url = format!("{}/api/v1/cases/{}/analysis/tree", self.api_url, case_id);
                match self.api_get(&url).await {
                    Ok(tree) => {
                        self.add_message("Analysis Tree:".to_string());
                        self.print_tree_node(&tree, 0);
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "recent" => {
                let url = format!("{}/api/v1/cases/{}/recent", self.api_url, case_id);
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(items) = val.as_array() {
                            self.add_message(format!("Recent Artifacts ({}):", items.len()));
                            let rows: Vec<Vec<String>> = items
                                .iter()
                                .map(|a| {
                                    vec![
                                        a["id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        a["artifact_type"].as_str().unwrap_or("?").to_string(),
                                        a["name"].as_str().unwrap_or("").to_string(),
                                        a["created_at"].as_str().unwrap_or("?").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Type", "Name", "Created"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "children" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /artifact children <parent_id>".to_string());
                    return;
                }
                let parent_id = parts[2];
                let url = format!(
                    "{}/api/v1/cases/{}/artifacts/{}/children",
                    self.api_url, case_id, parent_id
                );
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(items) = val.as_array() {
                            self.add_message(format!("Child Artifacts ({}):", items.len()));
                            let rows: Vec<Vec<String>> = items
                                .iter()
                                .map(|a| {
                                    vec![
                                        a["id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        a["artifact_type"].as_str().unwrap_or("?").to_string(),
                                        a["name"].as_str().unwrap_or("").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Type", "Name"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "history" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /artifact history <artifact_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/artifacts/{}/processing-history",
                    self.api_url, case_id, parts[2]
                );
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(items) = val.as_array() {
                            self.add_message(format!("Processing History ({}):", items.len()));
                            let rows: Vec<Vec<String>> = items
                                .iter()
                                .map(|h| {
                                    vec![
                                        h["module_id"].as_str().unwrap_or("?").to_string(),
                                        h["status"].as_str().unwrap_or("?").to_string(),
                                        h["started_at"].as_str().unwrap_or("?").to_string(),
                                        h["completed_at"].as_str().unwrap_or("").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["Module", "Status", "Started", "Completed"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "delete" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /artifact delete <artifact_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/artifacts/{}",
                    self.api_url, case_id, parts[2]
                );
                match self.api_delete(&url).await {
                    Ok(_) => self.add_message(format!("Artifact {} deleted.", parts[2])),
                    Err(e) => self.add_message(e),
                }
            }
            // Default: treat as artifact ID
            artifact_id => {
                let url = format!(
                    "{}/api/v1/cases/{}/artifacts/{}",
                    self.api_url, case_id, artifact_id
                );
                match self.api_get(&url).await {
                    Ok(art) => {
                        self.add_message("Artifact Details:".to_string());
                        self.add_message(format!(
                            "  ID:       {}",
                            art["id"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Type:     {}",
                            art["artifact_type"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Parent:   {}",
                            art["parent_id"].as_str().unwrap_or("none")
                        ));
                        self.add_message(format!(
                            "  Created:  {}",
                            art["created_at"].as_str().unwrap_or("?")
                        ));
                        if let Some(meta) = art["metadata"].as_object() {
                            self.add_message("  Metadata:".to_string());
                            for (k, v) in meta {
                                let vs = match v {
                                    Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                };
                                self.add_message(Self::wrap_metadata_value(k, &vs));
                            }
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
        }
    }

    fn print_tree_node(&mut self, node: &Value, depth: usize) {
        let indent = "  ".repeat(depth + 1);
        let name = node["name"].as_str().unwrap_or("?");
        let node_type = node["node_type"].as_str().unwrap_or("");
        let count = node["count"].as_u64().unwrap_or(0);
        if count > 0 {
            self.add_message(format!("{}{} [{}] ({})", indent, name, node_type, count));
        } else {
            self.add_message(format!("{}{} [{}]", indent, name, node_type));
        }
        if let Some(children) = node["children"].as_array() {
            for child in children {
                self.print_tree_node(child, depth + 1);
            }
        }
    }

    // ---- Hex Dump ----

    async fn handle_hex(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message("Usage: /hex <artifact_id> [offset] [length]".to_string());
            return;
        }
        let artifact_id = parts[1];
        let offset = if parts.len() > 2 {
            parts[2].parse::<u64>().unwrap_or(0)
        } else {
            0
        };
        let limit = if parts.len() > 3 {
            parts[3].parse::<u64>().unwrap_or(256)
        } else {
            256
        };

        let url = format!(
            "{}/api/v1/cases/{}/artifacts/{}/hex?offset={}&limit={}",
            self.api_url, case_id, artifact_id, offset, limit
        );
        match self.api_get(&url).await {
            Ok(resp) => {
                self.add_message(format!(
                    "Hex dump of {} (offset {}, {} bytes):",
                    artifact_id, offset, limit
                ));
                if let Some(hex) = resp["hex"].as_str() {
                    let ascii = resp["ascii"].as_str().unwrap_or("");
                    // Display hex + ASCII side by side, 16 bytes per line
                    let hex_bytes: Vec<&str> = hex.split_whitespace().collect();
                    let ascii_chars: Vec<char> = ascii.chars().collect();
                    let mut addr = offset;
                    let mut idx = 0;
                    while idx < hex_bytes.len() {
                        let end = (idx + 16).min(hex_bytes.len());
                        let hex_line = hex_bytes[idx..end].join(" ");
                        let ascii_end = (idx + 16).min(ascii_chars.len());
                        let ascii_line: String = if idx < ascii_chars.len() {
                            ascii_chars[idx..ascii_end].iter().collect()
                        } else {
                            String::new()
                        };
                        self.add_message(format!(
                            "  {:08x}  {:<48}  |{}|",
                            addr, hex_line, ascii_line
                        ));
                        addr += 16;
                        idx += 16;
                    }
                } else {
                    self.add_message(
                        serde_json::to_string_pretty(&resp)
                            .unwrap_or_default()
                            .to_string(),
                    );
                }
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Bookmarks ----

    async fn handle_bookmark(&mut self, parts: &[&str], command: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message("Usage: /bookmark <list|add|remove|categories|addcat>".to_string());
            return;
        }
        match parts[1] {
            "list" => {
                let mut url = format!("{}/api/v1/cases/{}/bookmarks", self.api_url, case_id);
                if parts.len() > 2 {
                    url.push_str(&format!("?category={}", parts[2]));
                }
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(items) = val.as_array() {
                            self.add_message(format!("Bookmarks ({}):", items.len()));
                            let rows: Vec<Vec<String>> = items
                                .iter()
                                .map(|b| {
                                    vec![
                                        b["artifact_id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        b["category_name"].as_str().unwrap_or("").to_string(),
                                        elide(b["note"].as_str().unwrap_or(""), 40),
                                        b["created_at"].as_str().unwrap_or("?").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["Artifact", "Category", "Note", "Created"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "add" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /bookmark add <artifact_id> [note]".to_string());
                    return;
                }
                let note = if parts.len() > 3 {
                    command.splitn(4, ' ').nth(3).unwrap_or("")
                } else {
                    ""
                };
                let url = format!("{}/api/v1/cases/{}/bookmarks", self.api_url, case_id);
                let body = serde_json::json!({"artifact_id": parts[2], "note": note});
                match self.api_post(&url, &body).await {
                    Ok(_) => self.add_message(format!("Bookmarked artifact {}", parts[2])),
                    Err(e) => self.add_message(e),
                }
            }
            "remove" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /bookmark remove <artifact_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/bookmarks/{}",
                    self.api_url, case_id, parts[2]
                );
                match self.api_delete(&url).await {
                    Ok(_) => self.add_message(format!("Bookmark removed for {}", parts[2])),
                    Err(e) => self.add_message(e),
                }
            }
            "categories" => {
                let url = format!(
                    "{}/api/v1/cases/{}/bookmarks/categories",
                    self.api_url, case_id
                );
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(cats) = val.as_array() {
                            self.add_message(format!("Bookmark Categories ({}):", cats.len()));
                            let rows: Vec<Vec<String>> = cats
                                .iter()
                                .map(|c| {
                                    vec![
                                        c["id"].as_str().unwrap_or("?").to_string(),
                                        c["name"].as_str().unwrap_or("?").to_string(),
                                        c["color"].as_str().unwrap_or("").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Name", "Color"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "addcat" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /bookmark addcat <name> [color]".to_string());
                    return;
                }
                let color = if parts.len() > 3 { parts[3] } else { "#6c757d" };
                let url = format!(
                    "{}/api/v1/cases/{}/bookmarks/categories",
                    self.api_url, case_id
                );
                let body = serde_json::json!({"name": parts[2], "color": color});
                match self.api_post(&url, &body).await {
                    Ok(cat) => {
                        let id = cat["id"].as_str().unwrap_or("?");
                        self.add_message(format!("Created category '{}' ({})", parts[2], id));
                    }
                    Err(e) => self.add_message(e),
                }
            }
            _ => self.add_message(
                "Unknown bookmark command. Use: list, add, remove, categories, addcat".to_string(),
            ),
        }
    }

    // ---- Modules ----

    async fn handle_module(&mut self, parts: &[&str], _command: &str) {
        if parts.len() < 2 {
            self.add_message("Usage: /module <list|run|jobs|job>".to_string());
            return;
        }
        match parts[1] {
            "list" => {
                let mut url = format!("{}/api/v1/modules", self.api_url);
                if parts.len() > 2 && parts[2] == "--type" && parts.len() > 3 {
                    url.push_str(&format!("?artifact_type={}", parts[3]));
                }
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(mods) = val.as_array() {
                            self.add_message(format!("Modules ({}):", mods.len()));
                            let rows: Vec<Vec<String>> = mods
                                .iter()
                                .map(|m| {
                                    vec![
                                        m["id"].as_str().unwrap_or("?").to_string(),
                                        m["name"].as_str().unwrap_or("?").to_string(),
                                        m["version"].as_str().unwrap_or("").to_string(),
                                        format!("{}", m["artifact_types"]),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Name", "Version", "Types"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "run" => {
                let case_id = match self.require_case() {
                    Some(id) => id,
                    None => {
                        self.no_case_msg();
                        return;
                    }
                };
                if parts.len() < 4 {
                    self.add_message("Usage: /module run <module_id> <artifact_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/artifacts/{}/run_module",
                    self.api_url, case_id, parts[3]
                );
                let body = serde_json::json!({"module_id": parts[2]});
                match self.api_post(&url, &body).await {
                    Ok(resp) => {
                        let job_id = resp["job_id"].as_str().unwrap_or("?");
                        let status = resp["status"].as_str().unwrap_or("?");
                        self.add_message(format!(
                            "Module job started: {} (status: {})",
                            job_id, status
                        ));
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "jobs" => {
                let case_id = match self.require_case() {
                    Some(id) => id,
                    None => {
                        self.no_case_msg();
                        return;
                    }
                };
                let url = format!("{}/api/v1/cases/{}/jobs", self.api_url, case_id);
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(jobs) = val.as_array() {
                            self.add_message(format!("Jobs ({}):", jobs.len()));
                            let rows: Vec<Vec<String>> = jobs
                                .iter()
                                .map(|j| {
                                    vec![
                                        j["id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        j["module_id"].as_str().unwrap_or("?").to_string(),
                                        j["status"].as_str().unwrap_or("?").to_string(),
                                        j["created_at"].as_str().unwrap_or("?").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Module", "Status", "Created"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "job" => {
                let case_id = match self.require_case() {
                    Some(id) => id,
                    None => {
                        self.no_case_msg();
                        return;
                    }
                };
                if parts.len() < 3 {
                    self.add_message("Usage: /module job <job_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/jobs/{}",
                    self.api_url, case_id, parts[2]
                );
                match self.api_get(&url).await {
                    Ok(job) => {
                        self.add_message("Job Details:".to_string());
                        self.add_message(format!(
                            "  ID:          {}",
                            job["id"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Module:      {}",
                            job["module_id"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Artifact:    {}",
                            job["artifact_id"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Status:      {}",
                            job["status"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Created:     {}",
                            job["created_at"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Started:     {}",
                            job["started_at"].as_str().unwrap_or("")
                        ));
                        self.add_message(format!(
                            "  Completed:   {}",
                            job["completed_at"].as_str().unwrap_or("")
                        ));
                    }
                    Err(e) => self.add_message(e),
                }
            }
            _ => self.add_message("Unknown module command. Use: list, run, jobs, job".to_string()),
        }
    }

    // ---- Hash Sets ----

    async fn handle_hashset(&mut self, parts: &[&str], _command: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message("Usage: /hashset <list|create|delete|check>".to_string());
            return;
        }
        match parts[1] {
            "list" => {
                let url = format!("{}/api/v1/cases/{}/hash_sets", self.api_url, case_id);
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(sets) = val.as_array() {
                            self.add_message(format!("Hash Sets ({}):", sets.len()));
                            let rows: Vec<Vec<String>> = sets
                                .iter()
                                .map(|s| {
                                    vec![
                                        s["id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        s["name"].as_str().unwrap_or("?").to_string(),
                                        s["set_type"].as_str().unwrap_or("").to_string(),
                                        s["hash_algorithm"].as_str().unwrap_or("").to_string(),
                                        s["entry_count"].as_u64().unwrap_or(0).to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Name", "Type", "Algorithm", "Entries"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "create" => {
                if parts.len() < 3 {
                    self.add_message(
                        "Usage: /hashset create <name> [type] [algorithm]".to_string(),
                    );
                    return;
                }
                let set_type = if parts.len() > 3 { parts[3] } else { "known" };
                let algorithm = if parts.len() > 4 { parts[4] } else { "md5" };
                let url = format!("{}/api/v1/cases/{}/hash_sets", self.api_url, case_id);
                let body = serde_json::json!({"name": parts[2], "set_type": set_type, "hash_algorithm": algorithm});
                match self.api_post(&url, &body).await {
                    Ok(resp) => {
                        let id = resp["id"].as_str().unwrap_or("?");
                        self.add_message(format!("Created hash set '{}' ({})", parts[2], id));
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "delete" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /hashset delete <id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/hash_sets/{}",
                    self.api_url, case_id, parts[2]
                );
                match self.api_delete(&url).await {
                    Ok(_) => self.add_message(format!("Hash set {} deleted.", parts[2])),
                    Err(e) => self.add_message(e),
                }
            }
            "check" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /hashset check <artifact_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/artifacts/{}/hash_check",
                    self.api_url, case_id, parts[2]
                );
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(matches) = val.as_array() {
                            if matches.is_empty() {
                                self.add_message("No hash set matches found.".to_string());
                            } else {
                                self.add_message(format!("Hash Set Matches ({}):", matches.len()));
                                let rows: Vec<Vec<String>> = matches
                                    .iter()
                                    .map(|m| {
                                        vec![
                                            m["hash_value"].as_str().unwrap_or("?").to_string(),
                                            m["hash_set_name"].as_str().unwrap_or("?").to_string(),
                                            m["set_type"].as_str().unwrap_or("").to_string(),
                                            m["product_name"].as_str().unwrap_or("").to_string(),
                                        ]
                                    })
                                    .collect();
                                self.add_table(&["Hash", "Set", "Type", "Product"], &rows);
                            }
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            _ => self.add_message(
                "Unknown hashset command. Use: list, create, delete, check".to_string(),
            ),
        }
    }

    // ---- Profiles ----

    async fn handle_profile(&mut self, parts: &[&str], _command: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message("Usage: /profile <list|create|activate|delete>".to_string());
            return;
        }
        match parts[1] {
            "list" => {
                let url = format!("{}/api/v1/cases/{}/profiles", self.api_url, case_id);
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(profiles) = val.as_array() {
                            self.add_message(format!("Profiles ({}):", profiles.len()));
                            let rows: Vec<Vec<String>> = profiles
                                .iter()
                                .map(|p| {
                                    vec![
                                        p["id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        p["name"].as_str().unwrap_or("?").to_string(),
                                        if p["is_active"].as_bool().unwrap_or(false) {
                                            "ACTIVE"
                                        } else {
                                            ""
                                        }
                                        .to_string(),
                                        format!("{}", p["enabled_modules"]),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Name", "Active", "Modules"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "create" => {
                if parts.len() < 3 {
                    self.add_message(
                        "Usage: /profile create <name> [module1,module2,...]".to_string(),
                    );
                    return;
                }
                let modules: Vec<&str> = if parts.len() > 3 {
                    parts[3].split(',').collect()
                } else {
                    Vec::new()
                };
                let url = format!("{}/api/v1/cases/{}/profiles", self.api_url, case_id);
                let body = serde_json::json!({
                    "name": parts[2],
                    "description": "",
                    "enabled_modules": modules,
                    "disabled_modules": []
                });
                match self.api_post(&url, &body).await {
                    Ok(resp) => {
                        let name = resp["name"]
                            .as_str()
                            .or_else(|| resp["profile"]["name"].as_str())
                            .unwrap_or("?");
                        self.add_message(format!("Created profile: {}", name));
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "activate" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /profile activate <profile_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/profiles/{}/activate",
                    self.api_url, case_id, parts[2]
                );
                let body = serde_json::json!({});
                match self.api_post(&url, &body).await {
                    Ok(_) => self.add_message(format!("Profile {} activated.", parts[2])),
                    Err(e) => self.add_message(e),
                }
            }
            "delete" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /profile delete <profile_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/profiles/{}",
                    self.api_url, case_id, parts[2]
                );
                match self.api_delete(&url).await {
                    Ok(_) => self.add_message(format!("Profile {} deleted.", parts[2])),
                    Err(e) => self.add_message(e),
                }
            }
            _ => self.add_message(
                "Unknown profile command. Use: list, create, activate, delete".to_string(),
            ),
        }
    }

    // ---- Audit Log ----

    async fn handle_audit(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        let limit = if parts.len() > 1 {
            parts[1].parse::<i64>().unwrap_or(50)
        } else {
            50
        };
        let url = format!(
            "{}/api/v1/cases/{}/audit_log?limit={}",
            self.api_url, case_id, limit
        );
        match self.api_get(&url).await {
            Ok(val) => {
                // Response may be { events: [...], total: N } or direct array
                let events = val["events"].as_array().or_else(|| val.as_array());
                if let Some(entries) = events {
                    let total = val["total"].as_u64().unwrap_or(entries.len() as u64);
                    self.add_message(format!("Audit Log ({} of {}):", entries.len(), total));
                    let rows: Vec<Vec<String>> = entries
                        .iter()
                        .map(|e| {
                            vec![
                                e["timestamp"].as_str().unwrap_or("?").to_string(),
                                e["actor"].as_str().unwrap_or("").to_string(),
                                e["action"].as_str().unwrap_or("?").to_string(),
                                e["resource_type"].as_str().unwrap_or("").to_string(),
                                e["details"]
                                    .as_str()
                                    .unwrap_or("")
                                    .chars()
                                    .take(30)
                                    .collect(),
                            ]
                        })
                        .collect();
                    self.add_table(&["Time", "Actor", "Action", "Resource", "Details"], &rows);
                }
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Filters ----

    async fn handle_filter(&mut self, parts: &[&str], command: &str) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message("Usage: /filter <list|create|get|apply|delete>".to_string());
            return;
        }
        match parts[1] {
            "list" => {
                let url = format!("{}/api/v1/cases/{}/filters", self.api_url, case_id);
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(filters) = val.as_array() {
                            self.add_message(format!("Filters ({}):", filters.len()));
                            let rows: Vec<Vec<String>> = filters
                                .iter()
                                .map(|f| {
                                    vec![
                                        f["id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        f["name"].as_str().unwrap_or("?").to_string(),
                                        f["description"].as_str().unwrap_or("").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Name", "Description"], &rows);
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "create" => {
                // /filter create <name> <json_condition>
                if parts.len() < 4 {
                    self.add_message("Usage: /filter create <name> <json_condition>".to_string());
                    self.add_message("  Example: /filter create MyFilter {\"type\":\"ArtifactType\",\"artifact_type\":\"FileEntry\"}".to_string());
                    return;
                }
                let json_str = command.splitn(4, ' ').nth(3).unwrap_or("{}");
                let filter_condition: Value = match serde_json::from_str(json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        self.add_message(format!("Invalid JSON: {}", e));
                        return;
                    }
                };
                let url = format!("{}/api/v1/cases/{}/filters", self.api_url, case_id);
                let body = serde_json::json!({
                    "name": parts[2],
                    "description": "",
                    "filter": filter_condition
                });
                match self.api_post(&url, &body).await {
                    Ok(resp) => {
                        let id = resp["id"].as_str().unwrap_or("?");
                        self.add_message(format!("Created filter '{}' ({})", parts[2], id));
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "get" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /filter get <filter_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/filters/{}",
                    self.api_url, case_id, parts[2]
                );
                match self.api_get(&url).await {
                    Ok(f) => {
                        self.add_message("Filter Details:".to_string());
                        self.add_message(format!(
                            "  ID:          {}",
                            f["id"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Name:        {}",
                            f["name"].as_str().unwrap_or("?")
                        ));
                        self.add_message(format!(
                            "  Description: {}",
                            f["description"].as_str().unwrap_or("")
                        ));
                        self.add_message(format!("  Condition:   {}", f["filter"]));
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "apply" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /filter apply <filter_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/filters/{}/apply",
                    self.api_url, case_id, parts[2]
                );
                match self.api_get(&url).await {
                    Ok(val) => {
                        if let Some(items) = val.as_array() {
                            self.add_message(format!("Filter Results ({}):", items.len()));
                            let rows: Vec<Vec<String>> = items
                                .iter()
                                .take(50)
                                .map(|a| {
                                    vec![
                                        a["id"]
                                            .as_str()
                                            .unwrap_or("?")
                                            .chars()
                                            .take(8)
                                            .collect::<String>()
                                            + "...",
                                        a["artifact_type"].as_str().unwrap_or("?").to_string(),
                                        a["name"].as_str().unwrap_or("").to_string(),
                                    ]
                                })
                                .collect();
                            self.add_table(&["ID", "Type", "Name"], &rows);
                        } else {
                            self.add_message(format!(
                                "Result: {}",
                                serde_json::to_string_pretty(&val).unwrap_or_default()
                            ));
                        }
                    }
                    Err(e) => self.add_message(e),
                }
            }
            "delete" => {
                if parts.len() < 3 {
                    self.add_message("Usage: /filter delete <filter_id>".to_string());
                    return;
                }
                let url = format!(
                    "{}/api/v1/cases/{}/filters/{}",
                    self.api_url, case_id, parts[2]
                );
                match self.api_delete(&url).await {
                    Ok(_) => self.add_message(format!("Filter {} deleted.", parts[2])),
                    Err(e) => self.add_message(e),
                }
            }
            _ => self.add_message(
                "Unknown filter command. Use: list, create, get, apply, delete".to_string(),
            ),
        }
    }

    // ---- Export ----

    /// `/memory layer <image_id> [--start a] [--end a]` (ROADMAP §5.3): save the
    /// image's decoded physical layer as `<stem>.raw` beside its hole manifest
    /// `<stem>.manifest.json`, streaming the raw file chunk by chunk. The pure
    /// halves and the verdict rule are in `memory_layer.rs`.
    async fn handle_memory(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.get(1).copied() != Some("layer") {
            self.add_message(memory_layer::LAYER_USAGE.to_string());
            return;
        }
        let args = match memory_layer::parse_layer_args(parts) {
            Ok(args) => args,
            Err(refusal) => {
                self.add_message(refusal);
                return;
            }
        };
        let (manifest_url, raw_url) = memory_layer::layer_urls(&self.api_url, &case_id, &args);
        let stem = memory_layer::layer_file_stem(&args);

        let manifest = match self.api_get(&manifest_url).await {
            Ok(v) => v,
            Err(e) => {
                self.add_message(format!("Layer export refused or failed: {e}"));
                return;
            }
        };
        for line in memory_layer::manifest_summary(&manifest) {
            self.add_message(line);
        }
        let manifest_sha256 = manifest["manifest_sha256"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let expected = manifest["manifest"]["total_bytes"].as_u64().unwrap_or(0);
        let manifest_file = format!("{stem}.manifest.json");
        let pretty = serde_json::to_string_pretty(&manifest).unwrap_or_default();
        if let Err(e) = std::fs::write(&manifest_file, pretty) {
            self.add_message(format!("Failed to write {manifest_file}: {e}"));
            return;
        }

        let raw_file = format!("{stem}.raw");
        let mut res = match self.authed(self.client.get(&raw_url)).send().await {
            Ok(res) if res.status().is_success() => res,
            Ok(res) => {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                self.add_message(format!("Layer export failed: {status} {body}"));
                return;
            }
            Err(e) => {
                self.add_message(format!("Connection failed: {e}"));
                return;
            }
        };
        let header_sha256 = res
            .headers()
            .get("x-layer-manifest-sha256")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let mut out = match std::fs::File::create(&raw_file) {
            Ok(f) => std::io::BufWriter::new(f),
            Err(e) => {
                self.add_message(format!("Failed to create {raw_file}: {e}"));
                return;
            }
        };
        let mut written = 0u64;
        let mut stream_error: Option<String> = None;
        loop {
            match res.chunk().await {
                Ok(Some(chunk)) => {
                    use std::io::Write as _;
                    if let Err(e) = out.write_all(&chunk) {
                        stream_error = Some(format!("writing {raw_file}: {e}"));
                        break;
                    }
                    written += chunk.len() as u64;
                }
                Ok(None) => break,
                Err(e) => {
                    stream_error = Some(e.to_string());
                    break;
                }
            }
        }
        {
            use std::io::Write as _;
            if let Err(e) = out.flush() {
                stream_error.get_or_insert(format!("writing {raw_file}: {e}"));
            }
        }
        self.add_message(format!(
            "Saved {raw_file} ({written} bytes) and {manifest_file}"
        ));
        self.add_message(memory_layer::layer_verdict(
            expected,
            written,
            &manifest_sha256,
            header_sha256.as_deref(),
            stream_error.as_deref(),
        ));
    }

    async fn handle_export(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message(
                "Usage: /export <timeline|bookmarks|report|audit> [format] — \
                 timeline: json|csv|pdf|body; bookmarks: json|csv; \
                 report: pdf|html|xlsx|docx|rtf|xml; audit: csv"
                    .to_string(),
            );
            return;
        }
        let url = match export_url(&self.api_url, &case_id, parts[1], parts.get(2).copied()) {
            Ok(url) => url,
            Err(refusal) => {
                self.add_message(refusal);
                return;
            }
        };

        // For exports, we just trigger the download. In a TUI, we save to a file.
        // Authed like every other call: an export is a bulk read of case data,
        // which is the last request that should go out anonymously.
        match self.authed(self.client.get(&url)).send().await {
            Ok(res) if res.status().is_success() => {
                let content_type = res
                    .headers()
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_string();
                match res.bytes().await {
                    Ok(bytes) => {
                        let ext = export_extension(&content_type);
                        let filename = format!(
                            "seance_export_{}_{}.{}",
                            parts[1],
                            chrono::Utc::now().format("%Y%m%d_%H%M%S"),
                            ext
                        );
                        match std::fs::write(&filename, &bytes) {
                            Ok(_) => {
                                self.add_message(format!(
                                    "Exported to {} ({} bytes)",
                                    filename,
                                    bytes.len()
                                ));
                                // The streamed exports state their own
                                // completeness in a final verdict row, and
                                // their preamble says a file without one is a
                                // fragment. Apply that test here, as the web
                                // client does, rather than call every saved
                                // byte count a success (HUNT-041).
                                if parts[1] == "timeline"
                                    && (ext == "csv" || ext == "json" || ext == "body")
                                {
                                    self.add_message(export_verdict_message(
                                        &filename,
                                        export_verdict(ext, &bytes),
                                    ));
                                }
                            }
                            Err(e) => self.add_message(format!("Failed to write file: {}", e)),
                        }
                    }
                    Err(e) => self.add_message(format!("Failed to read response: {}", e)),
                }
            }
            Ok(res) => {
                // For audit CSV, it uses POST
                if parts[1] == "audit" {
                    match self.authed(self.client.post(&url)).send().await {
                        Ok(res) if res.status().is_success() => {
                            if let Ok(bytes) = res.bytes().await {
                                let filename = format!(
                                    "seance_export_audit_{}.csv",
                                    chrono::Utc::now().format("%Y%m%d_%H%M%S")
                                );
                                match std::fs::write(&filename, &bytes) {
                                    Ok(_) => self.add_message(format!(
                                        "Exported to {} ({} bytes)",
                                        filename,
                                        bytes.len()
                                    )),
                                    Err(e) => {
                                        self.add_message(format!("Failed to write file: {}", e))
                                    }
                                }
                            }
                        }
                        _ => self.add_message(format!("Export failed: {}", res.status())),
                    }
                } else {
                    self.add_message(format!("Export failed: {}", res.status()));
                }
            }
            Err(e) => self.add_message(format!("Connection failed: {}", e)),
        }
    }

    // ---- Status ----

    async fn handle_status(&mut self) {
        let url = format!("{}/api/v1/status", self.api_url);
        match self.api_get(&url).await {
            Ok(status) => {
                self.add_message("Processing Status:".to_string());
                self.add_message(
                    serde_json::to_string_pretty(&status)
                        .unwrap_or_default()
                        .to_string(),
                );
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Verify ----

    async fn handle_verify(&mut self, parts: &[&str]) {
        let case_id = match self.require_case() {
            Some(id) => id,
            None => {
                self.no_case_msg();
                return;
            }
        };
        if parts.len() < 2 {
            self.add_message("Usage: /verify <artifact_id>".to_string());
            return;
        }
        let url = format!(
            "{}/api/v1/cases/{}/artifacts/{}/verify",
            self.api_url, case_id, parts[1]
        );
        let body = serde_json::json!({});
        match self.api_post(&url, &body).await {
            Ok(result) => {
                self.add_message("Verification Result:".to_string());
                self.add_message(
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_default()
                        .to_string(),
                );
            }
            Err(e) => self.add_message(e),
        }
    }

    // ---- Browse ----

    async fn handle_browse(&mut self, parts: &[&str], command: &str) {
        let path = if parts.len() > 1 {
            command.trim_start_matches("/browse ").trim()
        } else {
            "."
        };
        let url = format!(
            "{}/api/v1/filesystem/browse?path={}",
            self.api_url,
            urlencoding::encode(path)
        );
        match self.api_get(&url).await {
            Ok(resp) => {
                let current = resp["current_path"].as_str().unwrap_or("?");
                self.add_message(format!("Directory: {}", current));
                if let Some(entries) = resp["entries"].as_array() {
                    let rows: Vec<Vec<String>> = entries
                        .iter()
                        .map(|e| {
                            let is_dir = e["is_dir"].as_bool().unwrap_or(false);
                            vec![
                                if is_dir { "DIR " } else { "    " }.to_string(),
                                e["name"].as_str().unwrap_or("?").to_string(),
                                if is_dir {
                                    "".to_string()
                                } else {
                                    format_size(e["size"].as_u64().unwrap_or(0))
                                },
                                e["modified"].as_str().unwrap_or("").to_string(),
                            ]
                        })
                        .collect();
                    self.add_table(&["", "Name", "Size", "Modified"], &rows);
                }
            }
            Err(e) => self.add_message(e),
        }
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];
    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

pub async fn run_repl(api_url: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = Arc::new(Mutex::new(App::new(api_url)));

    // Main Event Loop
    loop {
        {
            let app_data = app.lock().await;
            if app_data.should_quit {
                break;
            }
            terminal.draw(|f| ui(f, &app_data))?;
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                let mut app_data = app.lock().await;

                // Handle Ctrl+C first
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    app_data.should_quit = true;
                    continue;
                }

                match key.code {
                    KeyCode::Enter => {
                        app_data.execute_command().await;
                    }
                    KeyCode::Char(c) => {
                        app_data.input.push(c);
                    }
                    KeyCode::Backspace => {
                        app_data.input.pop();
                    }
                    KeyCode::Esc => {
                        app_data.input.clear();
                    }
                    KeyCode::Up => {
                        // Command history navigation
                        if !app_data.command_history.is_empty() {
                            let idx = match app_data.history_index {
                                Some(0) => 0,
                                Some(i) => i - 1,
                                None => app_data.command_history.len() - 1,
                            };
                            app_data.history_index = Some(idx);
                            app_data.input = app_data.command_history[idx].clone();
                        }
                    }
                    KeyCode::Down => {
                        // Command history navigation forward
                        if let Some(idx) = app_data.history_index {
                            if idx + 1 < app_data.command_history.len() {
                                app_data.history_index = Some(idx + 1);
                                app_data.input = app_data.command_history[idx + 1].clone();
                            } else {
                                app_data.history_index = None;
                                app_data.input.clear();
                            }
                        }
                    }
                    KeyCode::PageUp => {
                        app_data.scroll_offset = app_data.scroll_offset.saturating_add(10);
                    }
                    KeyCode::PageDown => {
                        app_data.scroll_offset = app_data.scroll_offset.saturating_sub(10);
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Min(1),    // Output area
                Constraint::Length(3), // Input area
                Constraint::Length(1), // Status Bar
            ]
            .as_ref(),
        )
        .split(f.area());

    // 1. Output Area (with scroll support)
    let output_height = chunks[0].height.saturating_sub(2) as usize; // Account for borders
    let total_messages = app.messages.len();
    let scroll = app.scroll_offset as usize;

    let messages: Vec<Line> = if total_messages > output_height {
        let end = total_messages.saturating_sub(scroll);
        let start = end.saturating_sub(output_height);
        app.messages[start..end]
            .iter()
            .map(|m| colorize_line(m))
            .collect()
    } else {
        app.messages.iter().map(|m| colorize_line(m)).collect()
    };

    let scroll_indicator = if scroll > 0 {
        format!(" [+{}]", scroll)
    } else {
        String::new()
    };

    let messages_area = Paragraph::new(messages)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Output Log{}", scroll_indicator)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(messages_area, chunks[0]);

    // 2. Input Area
    let prompt = match &app.active_case_name {
        Some(name) => format!("[{}] ", name),
        None => String::new(),
    };
    let input_text = format!("{}{}", prompt, app.input);
    let input = Paragraph::new(input_text.as_str())
        .style(match app.active_case_id {
            Some(_) => Style::default().fg(Color::Yellow),
            None => Style::default().fg(Color::White),
        })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Command Input"),
        );

    f.render_widget(input, chunks[1]);

    // Set cursor
    f.set_cursor_position((chunks[1].x + input_text.len() as u16 + 1, chunks[1].y + 1));

    // 3. Status Bar
    let status_text = format!(
        " Seance v{} | API: {} | Case: {} | /help",
        env!("CARGO_PKG_VERSION"),
        app.api_url,
        app.active_case_name.as_deref().unwrap_or("None")
    );
    let status_bar =
        Paragraph::new(status_text).style(Style::default().bg(Color::Blue).fg(Color::White));

    f.render_widget(status_bar, chunks[2]);
}

fn colorize_line(msg: &str) -> Line<'_> {
    if msg.starts_with("> ") {
        Line::from(Span::styled(msg, Style::default().fg(Color::Yellow)))
    } else if msg.starts_with("  ") && msg.contains(" | ") {
        // Table rows
        Line::from(Span::styled(msg, Style::default().fg(Color::Cyan)))
    } else if msg.starts_with("  -") || msg.starts_with("  =") {
        // Table separators
        Line::from(Span::styled(msg, Style::default().fg(Color::DarkGray)))
    } else if msg.contains("Error") || msg.contains("failed") || msg.contains("Failed") {
        Line::from(Span::styled(msg, Style::default().fg(Color::Red)))
    } else if msg.contains("Created")
        || msg.contains("deleted")
        || msg.contains("Switched")
        || msg.contains("Exported")
        || msg.contains("activated")
    {
        Line::from(Span::styled(msg, Style::default().fg(Color::Green)))
    } else {
        Line::from(Span::raw(msg))
    }
}

/// The marker every streamed export's verdict row begins with, as the server
/// writes it (`SEARCH_EXPORT_TERMINAL` in `seance_api`).
const EXPORT_VERDICT_MARKER: &str = "### END OF EXPORT ### VERDICT:";

/// The export kinds `/export` accepts and, for each, the formats the API
/// renders it in — the first of each list being the default when no format
/// is given. Every entry is a route the server registers
/// (`seance_api`: `/timeline/export/{csv,json,pdf,body}`,
/// `/bookmarks/export/{csv,json}`, `/export/{pdf,html,xlsx,docx,rtf,xml}`,
/// `/export/audit_log/csv`); a word not in the list is refused rather than
/// mapped to a neighbour, so the saved file is always the format asked for.
const EXPORT_FORMATS: &[(&str, &[&str])] = &[
    ("timeline", &["json", "csv", "pdf", "body"]),
    ("bookmarks", &["json", "csv"]),
    ("report", &["pdf", "html", "xlsx", "docx", "rtf", "xml"]),
    ("audit", &["csv"]),
];

/// The URL `/export <kind> [format]` fetches, or the message that refuses
/// it: an unknown kind names the kinds, an unknown format names the formats
/// that kind accepts.
fn export_url(
    api_url: &str,
    case_id: &str,
    kind: &str,
    format: Option<&str>,
) -> Result<String, String> {
    let Some((_, formats)) = EXPORT_FORMATS.iter().find(|(k, _)| *k == kind) else {
        let kinds: Vec<&str> = EXPORT_FORMATS.iter().map(|(k, _)| *k).collect();
        return Err(format!(
            "Unknown export type '{kind}'. Use: {}",
            kinds.join(", ")
        ));
    };
    let format = format.unwrap_or(formats[0]);
    if !formats.contains(&format) {
        return Err(format!(
            "Unknown {kind} export format '{format}'. Use: {} (default {})",
            formats.join(", "),
            formats[0]
        ));
    }
    let base = format!("{api_url}/api/v1/cases/{case_id}");
    Ok(match kind {
        // `body` is a file export, not an event export: one row per
        // FileEntry with its own MAC times, for mactime / log2timeline /
        // Timesketch.
        "timeline" => format!("{base}/timeline/export/{format}"),
        "bookmarks" => format!("{base}/bookmarks/export/{format}"),
        "report" => format!("{base}/export/{format}"),
        _ => format!("{base}/export/audit_log/csv"),
    })
}

/// The extension a saved export gets, from the response's `Content-Type`.
/// The two OOXML types are tested before the bare `xml` word they contain.
fn export_extension(content_type: &str) -> &'static str {
    if content_type.contains("csv") {
        "csv"
    } else if content_type.contains("pdf") {
        "pdf"
    } else if content_type.contains("html") {
        "html"
    } else if content_type.contains("spreadsheetml") {
        "xlsx"
    } else if content_type.contains("wordprocessingml") {
        "docx"
    } else if content_type.contains("rtf") {
        "rtf"
    } else if content_type.contains("xml") {
        "xml"
    } else if content_type.starts_with("text/plain") {
        // The body file: pipe-delimited text, no other export answers with
        // this type.
        "body"
    } else {
        "json"
    }
}

/// The verdict a streamed CSV or JSON export ends with, or `None` when the
/// file has no verdict row — which the file's own preamble defines as a
/// fragment that must not be tendered.
///
/// The test is the SHAPE the server gives the row, not the marker's presence:
/// the marker is quoted in the preamble's reading note and can sit in a hit
/// row, so a file cut off after two kilobytes still contains it. A whole CSV's
/// last line begins with a double quote and then the marker (no hit row can
/// begin a line that way); a whole JSON document's last member is the
/// `completeness` object whose `statement` begins with it; a whole body file's
/// last line is `# ` and then the marker (a row's first field is an MD5 or
/// empty, so no row begins with `#`).
pub(crate) fn export_verdict(ext: &str, bytes: &[u8]) -> Option<String> {
    match ext {
        "body" => {
            let text = String::from_utf8_lossy(bytes);
            let body = text.strip_suffix('\n').unwrap_or(&text);
            let last = body.rsplit('\n').next().unwrap_or("");
            last.strip_prefix("# ")
                .filter(|v| v.starts_with(EXPORT_VERDICT_MARKER))
                .map(str::to_string)
        }
        "csv" => {
            let text = String::from_utf8_lossy(bytes);
            let body = text.strip_suffix('\n').unwrap_or(&text);
            let last = body.rsplit('\n').next().unwrap_or("");
            let quoted = format!("\"{EXPORT_VERDICT_MARKER}");
            if !last.starts_with(&quoted) {
                return None;
            }
            // The verdict is the first (quoted) cell; `""` is a literal quote.
            let mut out = String::new();
            let mut chars = last[1..].chars().peekable();
            while let Some(c) = chars.next() {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        out.push('"');
                    } else {
                        break;
                    }
                } else {
                    out.push(c);
                }
            }
            Some(out)
        }
        "json" => {
            let doc: Value = serde_json::from_slice(bytes).ok()?;
            let statement = doc.get("completeness")?.get("statement")?.as_str()?;
            statement
                .starts_with(EXPORT_VERDICT_MARKER)
                .then(|| statement.to_string())
        }
        _ => None,
    }
}

/// What the examiner is told about a saved streamed export.
fn export_verdict_message(filename: &str, verdict: Option<String>) -> String {
    match verdict {
        Some(v) => {
            let text = v.strip_prefix(EXPORT_VERDICT_MARKER).unwrap_or(&v).trim();
            format!("{filename} — the file's own verdict: {text}")
        }
        None => format!(
            "{filename} is a FRAGMENT: it has no final verdict row, so the transfer was cut \
             short and rows are missing from the end. Its own preamble says such a file must \
             not be tendered. Re-run the export."
        ),
    }
}

/// Every command the dispatcher knows, for the did-you-mean suggestion.
const KNOWN_COMMANDS: &[&str] = &[
    "/memory",
    "/quit",
    "/exit",
    "/clear",
    "/help",
    "/login",
    "/unlock",
    "/logout",
    "/case",
    "/ingest",
    "/search",
    "/sweep",
    "/timeline",
    "/stats",
    "/duplicates",
    "/artifact",
    "/hex",
    "/bookmark",
    "/module",
    "/hashset",
    "/profile",
    "/audit",
    "/filter",
    "/export",
    "/status",
    "/verify",
    "/browse",
];

/// What `/help search` prints.
const SEARCH_HELP: &[&str] = &[
    "  /search <query>                  - Full-text search",
    "  /search <query> --regex          - Regex search",
    "  /search <query> --type <type>    - Filter by artifact type",
    "  /search <query> --ext .exe,.dll  - Filter by extension",
    "  /sweep <text> [--bytes <hex>]    - Case-wide byte sweep of the evidence bytes (text in",
    "                                     UTF-8, UTF-16LE/BE and any --codepage; --bytes hex)",
    "  /sweep ... --region live,slack,unallocated,recovered,raw  --ext .txt  --type FileContent",
    "  /sweep ... --path <prefix> --glob <glob> --max-hits <n> --max-bytes <n>",
    "  /sweep ... --resume <artifact_id>:<offset>   - Continue a sweep a ceiling cut",
    "      Every answer prints complete: true|false, each ceiling that was reached, and the",
    "      slack statement; a cut sweep prints the --resume token to continue it.",
];

/// The credential kinds `POST …/credential` takes, as `/unlock` names them.
const UNLOCK_KINDS: &[&str] = &[
    "bitlocker_recovery_password",
    "bitlocker_password",
    "luks_passphrase",
    "sevenz_password",
    "signal_ios_key_spec",
    "ios_backup_password",
    "signal_backup_passphrase",
    "whatsapp_key",
    "macos_keychain_password",
    "macos_system_key",
];

/// The kinds `POST …/unlock` takes, as `/unlock --read` names them.
const UNLOCK_READ_KINDS: &[&str] = &[
    "ios_backup_password",
    "bitlocker_password",
    "bitlocker_recovery_password",
    "luks_passphrase",
];

/// `/unlock <artifact_id> <kind> <secret…>`: the secret is everything after
/// the one whitespace character that ends the kind, taken verbatim — leading
/// and trailing spaces included, since a password may have them and a trimmed
/// password is a different one (SEC-204 review). A secret that is nothing but
/// whitespace is refused.
fn unlock_args(command: &str) -> Option<(&str, &str, &str)> {
    let rest = command.trim_start().strip_prefix("/unlock")?.trim_start();
    let (artifact, rest) = rest.split_once(char::is_whitespace)?;
    let (kind, secret) = rest.trim_start().split_once(char::is_whitespace)?;
    (!secret.trim().is_empty()).then_some((artifact, kind, secret))
}

/// What an `/unlock` line asks for (HUNT-254).
#[derive(Debug, PartialEq, Eq)]
enum UnlockMode<'a> {
    /// `/unlock <artifact_id> <kind> <secret>`: one run with the secret
    /// (`POST …/credential`).
    Run(&'a str, &'a str, &'a str),
    /// `/unlock --read <artifact_id> <kind> <secret>`: unlock for reading
    /// (`POST …/unlock`) — the key held in the server's memory for this case.
    Read(&'a str, &'a str, &'a str),
    /// `/unlock --lock <artifact_id>`: forget it again (`DELETE …/unlock`).
    Lock(&'a str),
}

/// Parse an `/unlock` line; `None` is a usage error.
fn unlock_mode(command: &str) -> Option<UnlockMode<'_>> {
    let rest = command.trim_start().strip_prefix("/unlock")?.trim_start();
    if let Some(after) = rest.strip_prefix("--lock") {
        let artifact = after.trim();
        return (!artifact.is_empty() && !artifact.contains(char::is_whitespace))
            .then_some(UnlockMode::Lock(artifact));
    }
    if let Some(after) = rest.strip_prefix("--read") {
        // The same verbatim-secret rule as the run form.
        let (artifact, rest) = after.trim_start().split_once(char::is_whitespace)?;
        let (kind, secret) = rest.trim_start().split_once(char::is_whitespace)?;
        return (!secret.trim().is_empty()).then_some(UnlockMode::Read(artifact, kind, secret));
    }
    unlock_args(command).map(|(a, k, s)| UnlockMode::Run(a, k, s))
}

/// What `/search` prints about the search's scope, from the `universe` the
/// API returns with every search page (`SEARCH-002`).
///
/// A zero-hit search is read as "the term is not in the evidence", so it
/// carries the statement of what was searched. A response without `universe`
/// (an older server) says that the scope was not stated rather than saying
/// nothing. A search with hits makes no absence claim and prints nothing here.
fn search_scope_lines(resp: &serde_json::Value, total: u64) -> Vec<String> {
    if total > 0 {
        return Vec::new();
    }
    match resp["universe"]["statement"].as_str() {
        Some(statement) if !statement.is_empty() => {
            vec![format!("What was searched: {statement}")]
        }
        _ => vec![
            "The server did not state what this search covers, so no result here says the term \
             is absent from the evidence."
                .to_string(),
        ],
    }
}

#[cfg(test)]
mod search_scope_tests {
    use super::search_scope_lines;
    use serde_json::json;

    #[test]
    fn a_zero_hit_search_prints_what_was_searched() {
        let resp = json!({"results": [], "total_count": 0,
            "universe": {"statement": "This search covers the metadata of the artifacts ..."}});
        let lines = search_scope_lines(&resp, 0);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("This search covers the metadata")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_zero_hit_search_without_a_universe_says_the_scope_was_not_stated() {
        let lines = search_scope_lines(&json!({"results": [], "total_count": 0}), 0);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("did not state what this search covers")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_search_with_hits_prints_no_scope_paragraph() {
        let resp = json!({"universe": {"statement": "This search covers ..."}});
        assert!(search_scope_lines(&resp, 3).is_empty());
    }
}

#[cfg(test)]
mod sweep_command_tests {
    use super::{KNOWN_COMMANDS, SEARCH_HELP};

    #[test]
    fn sweep_is_known_and_advertised() {
        assert!(KNOWN_COMMANDS.contains(&"/sweep"), "{KNOWN_COMMANDS:?}");
        assert!(
            SEARCH_HELP
                .iter()
                .any(|l| l.trim_start().starts_with("/sweep")),
            "{SEARCH_HELP:?}"
        );
    }
}

#[cfg(test)]
mod unlock_kind_tests {
    use super::UNLOCK_KINDS;

    /// SEC-204. `/unlock` must name every kind `POST …/credential` takes —
    /// the iOS backup password and the Signal Android backup passphrase moved
    /// there from `run_module`'s retired `secrets` map — and nothing else.
    #[test]
    fn unlock_kinds_are_the_credential_route_kinds() {
        let mut ours: Vec<&str> = UNLOCK_KINDS.to_vec();
        let mut route: Vec<&str> = seance_core::credential::CredentialKind::ALL
            .iter()
            .map(|k| k.as_str())
            .collect();
        ours.sort_unstable();
        route.sort_unstable();
        assert_eq!(ours, route);
    }
}

#[cfg(test)]
mod tests {
    //! Tests for pure REPL helpers and state-only commands.
    //!
    //! Anything that hits the API (search, ingest, etc.) is excluded — those
    //! would need a stub HTTP server. What's covered here:
    //!   * `levenshtein` — used by the unknown-command suggestion path
    //!   * `format_size` — byte-count display helper
    //!   * `colorize_line` — log-line styling rules
    //!   * `App::add_message` — multi-line splitting
    //!   * `App::add_table` — header/row layout, empty rows
    //!   * `execute_command` for offline commands (`/quit`, `/exit`, `/clear`)
    //!     plus the unknown-command suggestion (uses levenshtein)

    /// `/export` reaches every report format the API renders, and a format
    /// it does not know is refused with the accepted set named — never
    /// silently mapped to another format (`/export report docx` once saved a
    /// PDF).
    #[test]
    fn export_url_names_every_format_the_api_renders_and_refuses_the_rest() {
        let api = "http://h";
        let case = "c1";
        let url = |kind: &str, format: Option<&str>| export_url(api, case, kind, format);
        for (format, route) in [
            ("pdf", "export/pdf"),
            ("html", "export/html"),
            ("xlsx", "export/xlsx"),
            ("docx", "export/docx"),
            ("rtf", "export/rtf"),
            ("xml", "export/xml"),
        ] {
            assert_eq!(
                url("report", Some(format)).unwrap(),
                format!("http://h/api/v1/cases/c1/{route}"),
                "{format}"
            );
        }
        // No format: each kind's default, stated in the help text.
        assert_eq!(
            url("report", None).unwrap(),
            "http://h/api/v1/cases/c1/export/pdf"
        );
        assert_eq!(
            url("timeline", None).unwrap(),
            "http://h/api/v1/cases/c1/timeline/export/json"
        );
        assert_eq!(
            url("bookmarks", None).unwrap(),
            "http://h/api/v1/cases/c1/bookmarks/export/json"
        );
        assert_eq!(
            url("audit", None).unwrap(),
            "http://h/api/v1/cases/c1/export/audit_log/csv"
        );
        assert_eq!(
            url("timeline", Some("body")).unwrap(),
            "http://h/api/v1/cases/c1/timeline/export/body"
        );

        // An unknown format is refused, and the refusal names the set.
        let refusal = url("report", Some("odt")).unwrap_err();
        assert!(refusal.contains("odt"), "{refusal}");
        for accepted in ["pdf", "html", "xlsx", "docx", "rtf", "xml"] {
            assert!(refusal.contains(accepted), "{refusal} lacks {accepted}");
        }
        let refusal = url("timeline", Some("docx")).unwrap_err();
        assert!(
            refusal.contains("csv") && refusal.contains("body") && refusal.contains("docx"),
            "{refusal}"
        );
        let refusal = url("bookmarks", Some("pdf")).unwrap_err();
        assert!(
            refusal.contains("csv") && refusal.contains("json"),
            "{refusal}"
        );
        let refusal = url("audit", Some("json")).unwrap_err();
        assert!(refusal.contains("csv"), "{refusal}");
        let refusal = url("evidence", None).unwrap_err();
        assert!(
            refusal.contains("timeline") && refusal.contains("report"),
            "{refusal}"
        );
    }

    /// The saved file's extension follows the response's `Content-Type`,
    /// including the three Office/RTF/XML types; an OOXML type contains the
    /// letters "xml" and must not be saved as `.xml`.
    #[test]
    fn export_extension_follows_the_content_type() {
        assert_eq!(export_extension("text/csv; charset=utf-8"), "csv");
        assert_eq!(export_extension("application/pdf"), "pdf");
        assert_eq!(export_extension("text/html; charset=utf-8"), "html");
        assert_eq!(
            export_extension("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            "xlsx"
        );
        assert_eq!(
            export_extension(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
            "docx"
        );
        assert_eq!(export_extension("application/rtf"), "rtf");
        assert_eq!(export_extension("application/xml"), "xml");
        assert_eq!(export_extension("text/plain; charset=utf-8"), "body");
        assert_eq!(export_extension("application/json"), "json");
        assert_eq!(export_extension("application/octet-stream"), "json");
    }

    /// A saved streamed export is judged by its verdict row, not by its byte
    /// count (HUNT-041).
    #[test]
    fn a_saved_export_reports_its_verdict_and_names_a_fragment() {
        let whole_csv = b"# export,timeline,,,,\n# how_to_read,\"ends with '### END OF EXPORT ### VERDICT:'\",,,,\nTimestamp,A\n1,x\n\"### END OF EXPORT ### VERDICT: COMPLETE. This file holds all 1 of 1 events, \"\"whole\"\".\",,,,\n";
        let verdict = export_verdict("csv", whole_csv).expect("a whole file has a verdict");
        assert!(
            verdict.starts_with("### END OF EXPORT ### VERDICT: COMPLETE."),
            "{verdict}"
        );
        assert!(
            verdict.contains("\"whole\""),
            "doubled quotes are unescaped: {verdict}"
        );
        let msg = export_verdict_message("t.csv", Some(verdict));
        assert!(msg.contains("the file's own verdict: COMPLETE."), "{msg}");

        // Cut after the preamble: the marker is present, the verdict row is not.
        let fragment = b"# export,timeline,,,,\n# how_to_read,\"ends with '### END OF EXPORT ### VERDICT:'\",,,,\nTimestamp,A\n1,x\n";
        assert!(export_verdict("csv", fragment).is_none());
        let msg = export_verdict_message("t.csv", None);
        assert!(
            msg.contains("FRAGMENT") && msg.contains("must not be tendered"),
            "{msg}"
        );

        let whole_json = br#####"{"export":"timeline","how_to_read":"ends with '### END OF EXPORT ### VERDICT:'","events":[{"a":"### END OF EXPORT ### VERDICT: forged"}],"completeness":{"complete":true,"statement":"### END OF EXPORT ### VERDICT: COMPLETE. All 1 events."}}"#####;
        assert!(export_verdict("json", whole_json)
            .unwrap()
            .contains("COMPLETE"));
        let cut_json = br#####"{"export":"timeline","how_to_read":"### END OF EXPORT ### VERDICT:","events":[{"a":"### END OF EXPORT ### VERDICT: forged"}"#####;
        assert!(export_verdict("json", cut_json).is_none());

        // The body file: the verdict is a '#' line, which mactime skips; a row
        // can quote the marker in its name and still not be one, because no
        // row begins with '#'.
        let whole_body = b"# export: mactime body file\n# how_to_read: ends with '# ### END OF EXPORT ### VERDICT:'\n|/a|1||0|0|0|1|0|0|0\n|/### END OF EXPORT ### VERDICT: forged|2||0|0|0|1|0|0|0\n# ### END OF EXPORT ### VERDICT: COMPLETE. This file holds all 2 of 2 FileEntry artifacts in the case.\n";
        let verdict = export_verdict("body", whole_body).expect("a whole body file has a verdict");
        assert!(
            verdict.starts_with("### END OF EXPORT ### VERDICT: COMPLETE."),
            "{verdict}"
        );
        let cut_body = b"# export: mactime body file\n# how_to_read: ends with '# ### END OF EXPORT ### VERDICT:'\n|/a|1||0|0|0|1|0|0|0\n|/### END OF EXPORT ### VERDICT: forged|2||0|0|0|1|0|0|0\n";
        assert!(export_verdict("body", cut_body).is_none());
    }
    use super::*;

    // -- authentication -----------------------------------------------------

    /// **BUG-130.** The REPL must carry a credential once logged in.
    ///
    /// It used to send none at all, which meant it worked only against a server
    /// with authentication disabled, and every action it took was
    /// unattributable in the audit log. `authed` is the single place that
    /// decides, so this pins its behaviour in both directions.
    #[test]
    fn requests_carry_the_token_once_logged_in_and_none_before() {
        let mut app = fresh_app();
        let client = reqwest::Client::new();

        // Before login: no header, so an authenticated server refuses and the
        // REPL says so rather than appearing to work.
        let anonymous = app
            .authed(client.get("http://localhost:0/x"))
            .build()
            .expect("builds");
        assert!(
            anonymous
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .is_none(),
            "a request before login must not carry a fabricated credential"
        );

        app.token = Some("a-test-token".to_string());
        let authenticated = app
            .authed(client.get("http://localhost:0/x"))
            .build()
            .expect("builds");
        assert_eq!(
            authenticated
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer a-test-token"),
        );
    }

    /// A 401 must tell the operator the interface can authenticate.
    ///
    /// Before `/login` existed the REPL could only report the bare status, and
    /// there was nothing an operator could do about it.
    #[tokio::test]
    async fn the_login_command_is_known_and_advertised() {
        let mut app = fresh_app();
        app.messages.clear();
        // Two arguments are required; one is a usage error, not a login attempt
        // against the network.
        app.handle_login(&["/login", "someone"]).await;
        assert!(
            app.messages.iter().any(|m| m.contains("Usage: /login")),
            "an incomplete /login must explain itself: {:?}",
            app.messages
        );
        assert!(
            app.messages.iter().any(|m| m.contains("web UI")),
            "the exposure of typing a password into this UI must be stated"
        );
        assert!(app.token.is_none(), "a failed login must leave no token");
    }

    /// `/unlock` takes everything after the kind as the secret, so a LUKS
    /// passphrase of several words arrives whole.
    #[test]
    fn unlock_keeps_a_multi_word_secret_whole() {
        assert_eq!(
            unlock_args("/unlock a1 luks_passphrase correct horse battery staple"),
            Some(("a1", "luks_passphrase", "correct horse battery staple"))
        );
        assert_eq!(unlock_args("/unlock a1 luks_passphrase"), None);
        assert_eq!(unlock_args("/unlock a1"), None);
    }

    /// SEC-204 review. A password may begin or end with a space (an iOS
    /// backup password is whatever the owner typed): after the one space that
    /// ends the kind, the secret is taken verbatim, not trimmed. A secret that
    /// is only whitespace is still refused.
    #[test]
    fn unlock_keeps_leading_and_trailing_spaces_in_the_secret() {
        assert_eq!(
            unlock_args("/unlock a1 ios_backup_password  pass word "),
            Some(("a1", "ios_backup_password", " pass word "))
        );
        assert_eq!(unlock_args("/unlock a1 ios_backup_password    "), None);
    }

    /// HUNT-254: `--read` unlocks for reading and `--lock` forgets; the
    /// secret is still everything after the kind, taken verbatim.
    #[test]
    fn unlock_read_and_lock_forms_are_parsed() {
        assert_eq!(
            unlock_mode("/unlock --read a1 bitlocker_password  pass word "),
            Some(UnlockMode::Read("a1", "bitlocker_password", " pass word "))
        );
        assert_eq!(
            unlock_mode("/unlock --lock a1"),
            Some(UnlockMode::Lock("a1"))
        );
        assert_eq!(
            unlock_mode("/unlock a1 luks_passphrase pp"),
            Some(UnlockMode::Run("a1", "luks_passphrase", "pp"))
        );
        assert_eq!(unlock_mode("/unlock --read a1 luks_passphrase"), None);
        assert_eq!(unlock_mode("/unlock --lock"), None);
    }

    /// The `--read` form's secret is redacted like the run form's.
    #[tokio::test]
    async fn an_unlock_read_secret_is_redacted_from_history_and_scrollback() {
        let mut app = fresh_app();
        let cmd = "/unlock --read a1 bitlocker_password bde-TEST secret";
        app.command_history.push(cmd.to_string());
        app.messages.push(format!("> {cmd}"));
        app.handle_unlock(cmd).await;
        assert!(
            !app.command_history.iter().any(|c| c.contains("bde-TEST")),
            "{:?}",
            app.command_history
        );
        assert!(
            !app.messages.iter().any(|m| m.contains("bde-TEST")),
            "{:?}",
            app.messages
        );
        assert!(
            app.command_history
                .iter()
                .any(|c| c == "/unlock --read a1 bitlocker_password ********"),
            "{:?}",
            app.command_history
        );
    }

    /// A secret typed into `/unlock` must not survive in anything the UI can
    /// replay, whether or not the request reached the server.
    #[tokio::test]
    async fn an_unlock_secret_is_redacted_from_history_and_scrollback() {
        let mut app = fresh_app();
        let cmd = "/unlock a1 bitlocker_password bde-TEST secret";
        app.command_history.push(cmd.to_string());
        app.messages.push(format!("> {cmd}"));
        app.handle_unlock(cmd).await;
        assert!(
            !app.command_history.iter().any(|c| c.contains("bde-TEST")),
            "{:?}",
            app.command_history
        );
        assert!(
            !app.messages.iter().any(|m| m.contains("bde-TEST")),
            "{:?}",
            app.messages
        );
        assert!(app
            .command_history
            .iter()
            .any(|c| c == "/unlock a1 bitlocker_password ********"));
    }

    /// The password must not survive in anything the UI can replay.
    #[tokio::test]
    async fn a_typed_password_is_redacted_from_history_and_scrollback() {
        let mut app = fresh_app();
        app.command_history.push("/login jo hunter2".to_string());
        app.messages.push("> /login jo hunter2".to_string());
        // The login itself fails — nothing is listening on port 0 — which is
        // the case that matters: redaction must not depend on success.
        app.handle_login(&["/login", "jo", "hunter2"]).await;

        assert!(
            !app.command_history.iter().any(|c| c.contains("hunter2")),
            "the password survived in the recallable history: {:?}",
            app.command_history
        );
        assert!(
            !app.messages.iter().any(|m| m.contains("hunter2")),
            "the password survived in the scrollback: {:?}",
            app.messages
        );
    }

    // -- levenshtein --------------------------------------------------------

    #[test]
    fn levenshtein_identical_strings_is_zero() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("foo", "foo"), 0);
        assert_eq!(levenshtein("/help", "/help"), 0);
    }

    #[test]
    fn levenshtein_one_edit_distance() {
        // Single substitution
        assert_eq!(levenshtein("foo", "fob"), 1);
        // Single insertion
        assert_eq!(levenshtein("foo", "fooo"), 1);
        // Single deletion
        assert_eq!(levenshtein("fooo", "foo"), 1);
    }

    #[test]
    fn levenshtein_empty_string_yields_other_length() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn levenshtein_typo_suggestion_path() {
        // The REPL suggests known commands when distance <= 2. Confirm the
        // intended typos are within threshold.
        assert!(levenshtein("/seach", "/search") <= 2);
        assert!(levenshtein("/hlp", "/help") <= 2);
        assert!(levenshtein("/quti", "/quit") <= 2);
    }

    #[test]
    fn levenshtein_distant_strings_do_not_trigger_suggestion() {
        // A wildly different command should be > 2 away from any known one,
        // so the REPL says "Unknown command" without a suggestion.
        assert!(levenshtein("/xyzzy", "/search") > 2);
    }

    // -- format_size --------------------------------------------------------

    #[test]
    fn format_size_picks_appropriate_unit() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
        // Just under the GB threshold stays in MB.
        assert_eq!(format_size((1024 * 1024 * 1024) - 1), "1024.0 MB");
    }

    // -- colorize_line ------------------------------------------------------
    //
    // We cannot easily compare the styled `Line` directly, but we can check
    // that the function does not panic on any of the rule branches.

    #[test]
    fn colorize_line_handles_each_style_branch() {
        let inputs = [
            "> user typed this",
            "  col1 | col2",
            "  --------",
            "  ========",
            "Error: something",
            "Connection failed",
            "Created case 42",
            "Module deleted",
            "Switched to case",
            "Exported PDF",
            "Profile activated",
            "ordinary log line",
            "",
        ];
        for s in inputs.iter() {
            let _line = colorize_line(s);
        }
    }

    // -- App state helpers --------------------------------------------------

    fn fresh_app() -> App {
        // App::new pre-populates with a banner; the banner is irrelevant to
        // these tests, so we just track post-construction state.
        App::new("http://localhost:0".to_string())
    }

    #[test]
    fn app_new_starts_with_no_active_case() {
        let app = fresh_app();
        assert!(app.active_case_id.is_none());
        assert!(app.active_case_name.is_none());
        assert!(!app.should_quit);
        assert!(app.input.is_empty());
        assert!(app.command_history.is_empty());
    }

    /// **A qualification comes at the end of a sentence.**
    ///
    /// The artifact view kept the first eighty characters of a metadata value
    /// and discarded the rest, with no ellipsis. This is a real cross-view
    /// verdict; at eighty characters an examiner saw the finding and none of
    /// the doubt attached to it.
    #[test]
    fn a_long_qualification_survives_the_artifact_view() {
        let verdict = "An independent scan found this structure and the kernel's module list \
                       does not contain it. UNLINKING a module from that list is the oldest \
                       and commonest way of hiding a loaded kernel module on Linux, and the \
                       module goes on running. It is also what a module part-way through \
                       loading or unloading looks like. This is worth examining; it is not \
                       by itself proof of any of the three.";

        let shown = App::wrap_metadata_value("verdict_meaning", verdict);

        assert!(
            shown.contains("not by itself proof"),
            "the qualification was cut off, leaving only the accusation:\n{shown}"
        );
        assert!(
            shown.contains("part-way through loading or unloading"),
            "the innocent explanation was cut off:\n{shown}"
        );
        assert!(shown.starts_with("    verdict_meaning: "));
        // And it must be laid out, not emitted as one enormous line.
        assert!(
            shown.lines().count() > 1,
            "a 400-character value must be wrapped, not run off the pane"
        );
        for line in shown.lines() {
            assert!(
                line.chars().count() <= 80,
                "line runs off the pane ({} chars): {line}",
                line.chars().count()
            );
        }
    }

    /// Wrapping must not corrupt what it lays out: every word survives, in
    /// order. A renderer that silently dropped one would be worse than the
    /// truncation it replaced.
    #[test]
    fn wrapping_preserves_every_word_in_order() {
        let value = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu \
                     xi omicron pi rho sigma tau upsilon phi chi psi omega";
        let shown = App::wrap_metadata_value("greek", value);

        let original: Vec<&str> = value.split_whitespace().collect();
        let rendered: Vec<&str> = shown
            .split_whitespace()
            .skip(1) // the "greek:" label
            .collect();
        assert_eq!(rendered, original, "wrapping altered the value");
    }

    /// A word longer than the line — a hash, a long path — gets its own line
    /// rather than being cut in half.
    #[test]
    fn an_over_long_word_is_not_cut_in_half() {
        let hash = "a".repeat(120);
        let shown = App::wrap_metadata_value("sha256", &hash);
        assert!(
            shown.contains(&hash),
            "the hash was broken up and is no longer the value it was"
        );
    }

    #[test]
    fn a_short_value_stays_on_one_line() {
        let shown = App::wrap_metadata_value("deleted", "true");
        assert_eq!(shown, "    deleted: true");
    }

    #[test]
    fn an_empty_value_still_names_its_key() {
        let shown = App::wrap_metadata_value("note", "");
        assert_eq!(shown, "    note:");
    }

    /// A table column has to fit the pane, so it really does cut. What it must
    /// not do is cut silently: an unmarked truncation gives an examiner no
    /// reason to open the full record.
    #[test]
    fn a_shortened_table_cell_is_marked_as_shortened() {
        assert_eq!(
            elide("short", 40),
            "short",
            "a value that fits is untouched"
        );
        assert_eq!(elide("", 40), "");

        let long = "the message was deleted by the user before the device was seized";
        let cell = elide(long, 40);
        assert!(
            cell.ends_with('…'),
            "a shortened cell must say it was shortened: {cell}"
        );
        assert!(cell.chars().count() <= 40, "and must still fit the column");
        assert!(long.starts_with(cell.trim_end_matches('…')));
    }

    /// Multi-byte characters must not be split, and the width is in characters
    /// rather than bytes.
    #[test]
    fn eliding_counts_characters_and_not_bytes() {
        let cyrillic = "сообщение было удалено пользователем";
        let cell = elide(cyrillic, 10);
        assert_eq!(cell.chars().count(), 10);
        assert!(cell.ends_with('…'));
    }

    /// **A table of non-ASCII evidence must line up.**
    ///
    /// Widths were measured in bytes while `{:width$}` pads by characters, so a
    /// Cyrillic cell — eighteen bytes, nine characters — was padded to eighteen
    /// and shifted every column after it on that row by nine. On a tool whose
    /// purpose is reading other people's data, a table of Russian or Chinese
    /// messages was unreadable.
    #[test]
    fn a_table_of_non_ascii_evidence_lines_up() {
        let mut app = fresh_app();
        let start = app.messages.len();
        app.add_table(
            &["sender", "message"],
            &[
                vec!["alice".into(), "hello".into()],
                vec!["алиса".into(), "сообщение".into()],
                vec!["爱丽丝".into(), "消息".into()],
            ],
        );

        // Header, separator, then one line per row.
        let lines: Vec<&String> = app.messages[start..].iter().collect();
        assert_eq!(lines.len(), 5, "header, rule and three rows");

        // Every row's separator must sit in the same terminal column.
        let column_of = |line: &str| {
            let cut = line.find('|').expect("a column separator");
            display_width(&line[..cut])
        };
        let expected = column_of(lines[0]);
        for line in &lines[2..] {
            assert_eq!(
                column_of(line),
                expected,
                "column boundary moved on a non-ASCII row:\n{}\n{}",
                lines[0],
                line
            );
        }
    }

    /// Width is terminal cells: a CJK ideograph is one character occupying two.
    #[test]
    fn display_width_counts_terminal_cells() {
        assert_eq!(display_width("hello"), 5);
        assert_eq!(display_width("сообщение"), 9, "Cyrillic is one cell each");
        assert_eq!(display_width("消息"), 4, "each ideograph takes two cells");
        assert_eq!(display_width(""), 0);
    }

    #[test]
    fn add_message_splits_multiline_input() {
        let mut app = fresh_app();
        let initial = app.messages.len();
        app.add_message("line1\nline2\nline3".to_string());
        assert_eq!(app.messages.len(), initial + 3);
        assert_eq!(app.messages[initial], "line1");
        assert_eq!(app.messages[initial + 1], "line2");
        assert_eq!(app.messages[initial + 2], "line3");
    }

    #[test]
    fn add_message_resets_scroll_offset() {
        let mut app = fresh_app();
        app.scroll_offset = 17;
        app.add_message("anything".to_string());
        assert_eq!(
            app.scroll_offset, 0,
            "new output should bring us back to bottom"
        );
    }

    #[test]
    fn add_table_emits_no_results_for_empty_rows() {
        let mut app = fresh_app();
        let before = app.messages.len();
        app.add_table(&["A", "B"], &[]);
        assert_eq!(app.messages.len(), before + 1);
        assert_eq!(app.messages.last().unwrap(), "  (no results)");
    }

    #[test]
    fn add_table_pads_columns_to_widest_cell() {
        let mut app = fresh_app();
        let before = app.messages.len();
        app.add_table(
            &["id", "name"],
            &[
                vec!["1".to_string(), "alpha".to_string()],
                vec!["100".to_string(), "longer-name".to_string()],
            ],
        );
        // Output: header + separator + 2 rows (some impls may add trailing
        // padding lines). At minimum we got more than 1 line, and every row
        // contains the column separator " | ".
        assert!(app.messages.len() > before + 2);
        for line in &app.messages[before..] {
            // Lines that aren't separators must contain the " | " column gap.
            if !line.contains('-') && !line.is_empty() {
                assert!(line.contains(" | "), "row missing separator: {:?}", line);
            }
        }
    }

    // -- execute_command (offline branches) ---------------------------------

    #[tokio::test]
    async fn execute_command_quit_sets_should_quit() {
        let mut app = fresh_app();
        app.input = "/quit".to_string();
        app.execute_command().await;
        assert!(app.should_quit);
    }

    #[tokio::test]
    async fn execute_command_exit_alias_sets_should_quit() {
        let mut app = fresh_app();
        app.input = "/exit".to_string();
        app.execute_command().await;
        assert!(app.should_quit);
    }

    #[tokio::test]
    async fn execute_command_clear_empties_messages() {
        let mut app = fresh_app();
        assert!(!app.messages.is_empty(), "banner should pre-populate");
        app.input = "/clear".to_string();
        app.execute_command().await;
        assert!(app.messages.is_empty());
    }

    #[tokio::test]
    async fn execute_command_records_history() {
        let mut app = fresh_app();
        app.input = "/help".to_string();
        app.execute_command().await;
        // History should contain the command we just ran.
        assert_eq!(
            app.command_history.last().map(|s| s.as_str()),
            Some("/help")
        );
    }

    #[tokio::test]
    async fn execute_command_skips_consecutive_duplicates_in_history() {
        let mut app = fresh_app();
        app.input = "/help".to_string();
        app.execute_command().await;
        app.input = "/help".to_string();
        app.execute_command().await;
        // Same command run twice in a row — history only records once.
        let count = app
            .command_history
            .iter()
            .filter(|c| c.as_str() == "/help")
            .count();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn execute_command_unknown_command_emits_suggestion() {
        let mut app = fresh_app();
        let before = app.messages.len();
        // "/sear" is close enough to "/search" (levenshtein 2) to trigger a
        // suggestion.
        app.input = "/sear".to_string();
        app.execute_command().await;
        let new_msgs = &app.messages[before..];
        let combined = new_msgs.join("\n");
        assert!(
            combined.contains("Did you mean"),
            "expected suggestion in output, got: {}",
            combined
        );
    }

    #[tokio::test]
    async fn execute_command_unknown_command_without_close_match_says_so() {
        let mut app = fresh_app();
        let before = app.messages.len();
        app.input = "/xyzzy".to_string();
        app.execute_command().await;
        let new_msgs = &app.messages[before..];
        let combined = new_msgs.join("\n");
        assert!(
            combined.contains("Unknown command"),
            "expected unknown-command notice, got: {}",
            combined
        );
        assert!(
            !combined.contains("Did you mean"),
            "should NOT suggest for distant typos, got: {}",
            combined
        );
    }

    #[tokio::test]
    async fn execute_command_empty_input_is_noop() {
        let mut app = fresh_app();
        let before_len = app.command_history.len();
        app.input = "".to_string();
        app.execute_command().await;
        // Empty input must not be saved to history.
        assert_eq!(app.command_history.len(), before_len);
    }
}
