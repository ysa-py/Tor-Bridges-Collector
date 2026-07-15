//! Parity port of `core/notifier.py`.
//!
//! Telegram notification and file uploader. Sends a formatted statistics
//! message and the ZIP archive to a Telegram channel/chat after each
//! collection run.
//!
//! Network calls are abstracted behind the `TelegramApi` trait so tests
//! can inject a mock. Production callers should use `ReqwestTelegramApi`
//! (gated behind the `network` Cargo feature).

use std::path::Path;

use serde_json::Value;

/// Trait abstracting the two Telegram Bot API calls used by this module.
/// Production impl uses `reqwest`; tests inject a mock.
pub trait TelegramApi: Sync {
    /// Mirror of `POST /bot{token}/sendMessage`. Returns `true` if HTTP 200.
    fn send_message(&self, token: &str, chat_id: &str, text: &str, parse_mode: &str) -> bool;

    /// Mirror of `POST /bot{token}/sendDocument`. Returns `true` if HTTP 200.
    /// `file_bytes` is the document content; `file_name` is the basename
    /// for the multipart upload.
    fn send_document(
        &self,
        token: &str,
        chat_id: &str,
        file_name: &str,
        file_bytes: &[u8],
        caption: &str,
    ) -> bool;
}

/// No-op Telegram API that always returns `false` (disabled). Used when
/// credentials are missing or in tests that don't care about network.
pub struct DisabledTelegramApi;

impl TelegramApi for DisabledTelegramApi {
    fn send_message(&self, _: &str, _: &str, _: &str, _: &str) -> bool {
        false
    }
    fn send_document(&self, _: &str, _: &str, _: &str, _: &[u8], _: &str) -> bool {
        false
    }
}

/// Mirror of Python's `TelegramNotifier`.
pub struct TelegramNotifier<'a> {
    token: String,
    chat: String,
    recent_hours: i64,
    api: &'a dyn TelegramApi,
    now_iso: String,
}

impl<'a> TelegramNotifier<'a> {
    /// Construct with explicit credentials and API. `now_iso` is injectable
    /// so tests can use a fixed timestamp.
    pub fn new(
        token: &str,
        chat: &str,
        recent_hours: i64,
        api: &'a dyn TelegramApi,
        now_iso: String,
    ) -> Self {
        Self {
            token: token.to_string(),
            chat: chat.to_string(),
            recent_hours,
            api,
            now_iso,
        }
    }

    /// Mirror of `_enabled()`. Returns `true` if both token and chat are set.
    pub fn enabled(&self) -> bool {
        !self.token.is_empty() && !self.chat.is_empty()
    }

    /// Mirror of `_api(method)`. Returns the full Bot API URL.
    pub fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{method}", self.token)
    }

    /// Mirror of `send_message(text, parse_mode="Markdown")`. Returns `true`
    /// if the message was sent successfully.
    pub fn send_message(&self, text: &str, parse_mode: &str) -> bool {
        if !self.enabled() {
            return false;
        }
        self.api
            .send_message(&self.token, &self.chat, text, parse_mode)
    }

    /// Mirror of `send_document(file_path, caption="")`. Returns `true` if
    /// the document was uploaded successfully. Returns `false` if disabled
    /// or if the file doesn't exist.
    pub fn send_document(&self, file_path: &Path, caption: &str) -> bool {
        if !self.enabled() {
            return false;
        }
        if !file_path.exists() {
            tracing::warn!("Telegram upload: file not found: {}", file_path.display());
            return false;
        }
        let file_name = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("document");
        let file_bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Telegram sendDocument read error: {e}");
                return false;
            }
        };
        // Python truncates caption to 1024 chars.
        let caption_truncated = if caption.len() > 1024 {
            &caption[..1024]
        } else {
            caption
        };
        self.api.send_document(
            &self.token,
            &self.chat,
            file_name,
            &file_bytes,
            caption_truncated,
        )
    }

    /// Mirror of `build_caption(stats)`. Returns a Markdown-formatted
    /// caption summarizing the collection stats.
    pub fn build_caption(&self, stats: &Value) -> String {
        // Python: `ts = utc_now().strftime("%Y-%m-%d %H:%M UTC")`
        // We use the injected `now_iso` and reformat it.
        let ts = self.format_ts();
        let bt = stats.get("by_transport").unwrap_or(&Value::Null);
        let _ = self.recent_hours; // explicit reference (Python: `rh  # noqa`)

        let cnt = |key: &str| -> String {
            stats
                .get(key)
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .to_string()
        };

        let bt_cnt =
            |key: &str| -> String { bt.get(key).and_then(Value::as_i64).unwrap_or(0).to_string() };

        let lines = [
            "*🌐 Tor Bridges Ultra — Iran Optimised*",
            &format!("_Updated: {ts}_"),
            "",
            "*📦 Full Archive:*",
            &format!(
                "• obfs4: `{}`  |  WebTunnel: `{}`",
                bt_cnt("obfs4"),
                bt_cnt("webtunnel")
            ),
            &format!(
                "• Snowflake: `{}`  |  meek-lite: `{}`",
                bt_cnt("snowflake"),
                bt_cnt("meek_lite")
            ),
            &format!("• Vanilla: `{}`", bt_cnt("vanilla")),
            "",
            "*✅ Tested & Reachable:*",
            &format!(
                "• Total passing: `{}` / `{}` tested",
                cnt("passing"),
                cnt("tested")
            ),
            "",
            "*⚡ Iran Packs:*",
            "• `export/iran_pack.txt` — Top scored for Iran",
            "• `export/iran_cut_pack.txt` — Internet cut survival",
            "",
            "*📊 Transport Guide:*",
            "Snowflake ➔ WebTunnel ➔ obfs4 ➔ meek ➔ Vanilla",
            "_(best for Iran DPI → least effective)_",
            "",
            "━━━━━━━━━━━━━━━━━━━━━",
            "_ZIP contains: Full Archive / Fresh 72h / Tested / Iran Optimised_",
        ];
        lines.join("\n")
    }

    /// Mirror of `notify(stats, zip_path=None)`. Sends the stats message
    /// and optionally uploads the ZIP archive.
    pub fn notify(&self, stats: &Value, zip_path: Option<&Path>) {
        let caption = self.build_caption(stats);
        if let Some(path) = zip_path {
            if path.exists() {
                self.send_document(path, &caption);
            } else {
                self.send_message(&caption, "Markdown");
            }
        } else {
            self.send_message(&caption, "Markdown");
        }
    }

    /// Format `self.now_iso` as `YYYY-MM-DD HH:MM UTC` to match Python's
    /// `strftime("%Y-%m-%d %H:%M UTC")`.
    fn format_ts(&self) -> String {
        // Try parsing the ISO string; on failure, return it unchanged.
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&self.now_iso) {
            return dt.format("%Y-%m-%d %H:%M UTC").to_string();
        }
        self.now_iso.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct MockApi {
        message_called: std::sync::Mutex<bool>,
        document_called: std::sync::Mutex<bool>,
    }

    impl MockApi {
        fn new() -> Self {
            Self {
                message_called: std::sync::Mutex::new(false),
                document_called: std::sync::Mutex::new(false),
            }
        }
    }

    impl TelegramApi for MockApi {
        fn send_message(&self, _: &str, _: &str, _: &str, _: &str) -> bool {
            *self.message_called.lock().unwrap() = true;
            true
        }
        fn send_document(&self, _: &str, _: &str, _: &str, _: &[u8], _: &str) -> bool {
            *self.document_called.lock().unwrap() = true;
            true
        }
    }

    #[test]
    fn enabled_returns_false_when_credentials_missing() {
        let api = MockApi::new();
        let n = TelegramNotifier::new("", "", 72, &api, "2026-06-28T12:00:00+00:00".into());
        assert!(!n.enabled());
    }

    #[test]
    fn enabled_returns_true_when_credentials_present() {
        let api = MockApi::new();
        let n = TelegramNotifier::new(
            "token",
            "chat",
            72,
            &api,
            "2026-06-28T12:00:00+00:00".into(),
        );
        assert!(n.enabled());
    }

    #[test]
    fn api_url_formats_correctly() {
        let api = MockApi::new();
        let n = TelegramNotifier::new(
            "ABC123",
            "chat",
            72,
            &api,
            "2026-06-28T12:00:00+00:00".into(),
        );
        assert_eq!(
            n.api_url("sendMessage"),
            "https://api.telegram.org/botABC123/sendMessage"
        );
    }

    #[test]
    fn send_message_returns_false_when_disabled() {
        let api = MockApi::new();
        let n = TelegramNotifier::new("", "", 72, &api, "2026-06-28T12:00:00+00:00".into());
        assert!(!n.send_message("hello", "Markdown"));
        assert!(!*api.message_called.lock().unwrap());
    }

    #[test]
    fn send_message_calls_api_when_enabled() {
        let api = MockApi::new();
        let n = TelegramNotifier::new("tok", "chat", 72, &api, "2026-06-28T12:00:00+00:00".into());
        assert!(n.send_message("hello", "Markdown"));
        assert!(*api.message_called.lock().unwrap());
    }

    #[test]
    fn send_document_returns_false_when_file_missing() {
        let api = MockApi::new();
        let n = TelegramNotifier::new("tok", "chat", 72, &api, "2026-06-28T12:00:00+00:00".into());
        assert!(!n.send_document(Path::new("/nonexistent/file.zip"), "caption"));
        assert!(!*api.document_called.lock().unwrap());
    }

    #[test]
    fn send_document_calls_api_when_file_exists() {
        let dir = std::env::temp_dir().join(format!("notifier_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.zip");
        std::fs::write(&path, b"fake zip content").unwrap();

        let api = MockApi::new();
        let n = TelegramNotifier::new("tok", "chat", 72, &api, "2026-06-28T12:00:00+00:00".into());
        assert!(n.send_document(&path, "caption"));
        assert!(*api.document_called.lock().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_caption_includes_key_sections() {
        let api = MockApi::new();
        let n = TelegramNotifier::new("tok", "chat", 72, &api, "2026-06-28T12:00:00+00:00".into());
        let stats = json!({
            "by_transport": {"obfs4": 10, "webtunnel": 5, "snowflake": 3, "meek_lite": 2, "vanilla": 8},
            "passing": 12,
            "tested": 28,
        });
        let caption = n.build_caption(&stats);
        assert!(caption.contains("Tor Bridges Ultra — Iran Optimised"));
        assert!(caption.contains("Updated: 2026-06-28 12:00 UTC"));
        assert!(caption.contains("obfs4: `10`"));
        assert!(caption.contains("Snowflake: `3`"));
        assert!(caption.contains("Total passing: `12` / `28` tested"));
        assert!(caption.contains("Transport Guide"));
    }
}
