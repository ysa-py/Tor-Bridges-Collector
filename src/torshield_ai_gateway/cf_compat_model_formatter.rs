// Parity port of `torshield_ai_gateway/cf_compat_model_formatter.py` — correct
// model-ID formatting per Cloudflare AI Gateway endpoint type, plus gateway-name
// extraction and endpoint URL builders.
//
// All functions are deterministic ports. The Python `log.warning` side effect in
// `extract_gateway_name` is intentionally dropped (observable output unchanged).
// `get_portkey_safe_model` reads the `PORTKEY_HEALTH_MODEL` environment variable
// exactly like the Python original.

use std::sync::OnceLock;

use regex::Regex;

/// Hardcoded static fallback models (used when the brain returns 0 models).
pub const STATIC_FALLBACK_MODELS: [&str; 14] = [
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/qwen/qwq-32b",
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
    "@cf/mistral/mistral-7b-instruct-v0.1",
    "@cf/google/gemma-7b-it",
    "@cf/meta/llama-2-7b-chat-int8",
    "@cf/openai/gpt-oss-120b",
    "@cf/nvidia/nemotron-3-120b-a12b",
    "@cf/meta/llama-4-scout-17b-16e-instruct",
    "@cf/zai-org/glm-4.7-flash",
    "@cf/microsoft/phi-4",
    "@cf/mistral/mistral-large-2407",
    "@cf/google/gemma-3-27b-it",
];

/// Portkey-compatible model names (never use `@cf/` models with Portkey).
pub const PORTKEY_SAFE_MODELS: [&str; 7] = [
    "llama3.1-70b",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "gpt-4o-mini",
    "mistral-7b-instruct",
    "meta/llama-3.1-70b-instruct",
    "meta/llama-3.1-8b-instruct",
];

/// Add the `workers-ai/` prefix to `@cf/` models for the `/compat/` endpoint.
pub fn format_model_for_compat_endpoint(model_id: &str) -> String {
    if model_id.is_empty() {
        return model_id.to_string();
    }
    // Already has a provider scope prefix (not @cf/) -> leave unchanged.
    if model_id.contains('/') && !model_id.starts_with("@cf/") {
        return model_id.to_string();
    }
    // @cf/ model without the workers-ai/ prefix -> add it.
    if model_id.starts_with("@cf/") {
        return format!("workers-ai/{model_id}");
    }
    // Already has workers-ai/ prefix, or unknown format -> return as-is.
    model_id.to_string()
}

/// Format model for the CF REST API endpoint (strip `workers-ai/` from @cf/).
pub fn format_model_for_rest_api(model_id: &str) -> String {
    if let Some(rest) = model_id.strip_prefix("workers-ai/@cf/") {
        return format!("@cf/{rest}");
    }
    model_id.to_string()
}

/// Format model for the CF native Workers-AI path endpoint (strip `workers-ai/`).
pub fn format_model_for_native_path(model_id: &str) -> String {
    model_id
        .strip_prefix("workers-ai/")
        .unwrap_or(model_id)
        .to_string()
}

/// Returns true if the model is a Cloudflare Workers-AI model.
pub fn is_cf_model(model_id: &str) -> bool {
    // Python: `model_id.replace("workers-ai/", "")` replaces ALL occurrences.
    model_id.replace("workers-ai/", "").starts_with("@cf/")
}

/// Returns a Portkey-compatible model ID, never an `@cf/` model.
pub fn get_portkey_safe_model(preferred: &str) -> String {
    if !preferred.is_empty() && !is_cf_model(preferred) && !preferred.starts_with("workers-ai/") {
        return preferred.to_string();
    }
    let env_model = std::env::var("PORTKEY_HEALTH_MODEL")
        .unwrap_or_default()
        .trim()
        .to_string();
    if !env_model.is_empty() && !is_cf_model(&env_model) && !env_model.starts_with("workers-ai/") {
        return env_model;
    }
    PORTKEY_SAFE_MODELS[0].to_string()
}

fn gateway_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"gateway\.ai\.cloudflare\.com/v1/[^/]+/([^/]+)/?$")
            .expect("static gateway-name regex is valid")
    })
}

/// Robustly extract the gateway name from a `CF_AI_GATEWAY_URL_N` value.
pub fn extract_gateway_name(gateway_url: &str) -> String {
    if gateway_url.is_empty() {
        return String::new();
    }
    let mut url = gateway_url.trim().trim_end_matches('/').to_string();

    for suffix in [
        "/compat/chat/completions",
        "/workers-ai/v1/chat/completions",
        "/compat",
        "/workers-ai/v1",
        "/workers-ai",
    ] {
        if url.ends_with(suffix) {
            url.truncate(url.len() - suffix.len());
            break;
        }
    }

    if let Some(caps) = gateway_name_re().captures(&url) {
        if let Some(m) = caps.get(1) {
            return m.as_str().to_string();
        }
    }

    if !url.contains('/') && !url.contains('.') {
        return url;
    }

    // Python logs a warning here; observable return value is the empty string.
    String::new()
}

/// Build the FORMAT-1 (REST API) chat-completions URL.
pub fn build_format1_url(account_id: &str) -> String {
    format!("https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1/chat/completions")
}

/// Build the FORMAT-3 (`/compat/`) chat-completions URL.
pub fn build_format3_url(account_id: &str, gateway_name: &str) -> String {
    format!(
        "https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_name}/compat/chat/completions"
    )
}

/// Build the FORMAT-2 (native path) URL with the model in the path.
pub fn build_format2_url(account_id: &str, gateway_name: &str, model_id: &str) -> String {
    let clean_model = format_model_for_native_path(model_id);
    format!(
        "https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_name}/workers-ai/{clean_model}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_endpoint_formatting() {
        assert_eq!(format_model_for_compat_endpoint(""), "");
        assert_eq!(
            format_model_for_compat_endpoint("@cf/meta/llama-3.3-70b-instruct-fp8-fast"),
            "workers-ai/@cf/meta/llama-3.3-70b-instruct-fp8-fast"
        );
        assert_eq!(
            format_model_for_compat_endpoint("openai/gpt-4o-mini"),
            "openai/gpt-4o-mini"
        );
        assert_eq!(
            format_model_for_compat_endpoint("workers-ai/@cf/x"),
            "workers-ai/@cf/x"
        );
        assert_eq!(format_model_for_compat_endpoint("bare-model"), "bare-model");
    }

    #[test]
    fn rest_and_native_formatting() {
        assert_eq!(
            format_model_for_rest_api("workers-ai/@cf/meta/llama"),
            "@cf/meta/llama"
        );
        assert_eq!(
            format_model_for_rest_api("@cf/meta/llama"),
            "@cf/meta/llama"
        );
        assert_eq!(
            format_model_for_native_path("workers-ai/@cf/meta/llama"),
            "@cf/meta/llama"
        );
        assert_eq!(
            format_model_for_native_path("@cf/meta/llama"),
            "@cf/meta/llama"
        );
    }

    #[test]
    fn is_cf_model_detection() {
        assert!(is_cf_model("@cf/meta/llama"));
        assert!(is_cf_model("workers-ai/@cf/meta/llama"));
        assert!(!is_cf_model("openai/gpt-4o-mini"));
        assert!(!is_cf_model("llama3.1-70b"));
    }

    #[test]
    fn gateway_name_extraction() {
        assert_eq!(extract_gateway_name(""), "");
        assert_eq!(
            extract_gateway_name(
                "https://gateway.ai.cloudflare.com/v1/acct123/mygw/compat/chat/completions"
            ),
            "mygw"
        );
        assert_eq!(
            extract_gateway_name("https://gateway.ai.cloudflare.com/v1/acct123/mygw"),
            "mygw"
        );
        assert_eq!(extract_gateway_name("barename"), "barename");
        assert_eq!(extract_gateway_name("https://example.com/some/path"), "");
    }

    #[test]
    fn url_builders() {
        assert_eq!(
            build_format1_url("acct1"),
            "https://api.cloudflare.com/client/v4/accounts/acct1/ai/v1/chat/completions"
        );
        assert_eq!(
            build_format3_url("acct1", "gw1"),
            "https://gateway.ai.cloudflare.com/v1/acct1/gw1/compat/chat/completions"
        );
        assert_eq!(
            build_format2_url("acct1", "gw1", "workers-ai/@cf/meta/llama"),
            "https://gateway.ai.cloudflare.com/v1/acct1/gw1/workers-ai/@cf/meta/llama"
        );
    }
}
