//! Concrete collector implementations.
//!
//! * [`BridgeLineTextSource`] — any HTTPS endpoint serving newline-delimited
//!   bridge lines (covers GitHub raw lists, RSS/text mirrors, and plain lists).
//! * [`BridgeLineJsonSource`] — any HTTPS endpoint serving a JSON bridge list.
//! * [`GithubContentsSource`] — enumerates `.txt`/`.json` bridge-list files
//!   under a public GitHub repository directory via the contents API, then
//!   collects each file's raw `download_url`.

mod github;
mod text;

pub use github::GithubContentsSource;
pub use text::{BridgeLineJsonSource, BridgeLineTextSource};
