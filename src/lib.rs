use std::fmt::Debug;
use thiserror::Error;

mod cli;
mod engine;
mod input_analyzer;
mod sanitizer;

pub use cli::{CliConfig, Verbosity, read_args};
pub use engine::{build_json_report, run_sanitizer};
pub use input_analyzer::analyze_input;
pub use sanitizer::{
    ContentStatus, ProcessedResult, RemovedElement, Rules, create_sanitizer_rules, get_rules,
    sanitize_html,
};

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("Rejected content: {0}")]
    RejectedContent(String),
    #[error("Serde parser error: {0}")]
    ConfigParse(#[from] toml::de::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("HTTP rewriting error: {0}")]
    Rewriter(#[from] lol_html::errors::RewritingError),
    #[error("Generic error: {0}")]
    GenericError(String),
}
