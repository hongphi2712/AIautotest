//! AI analysis integration (DeepSeek, OpenAI-compatible chat completions).
//!
//! Token-cost discipline: the analyzer never ships raw bodies, headers, or
//! token *values* to the model. It builds a compact, redacted context
//! (ordered steps, token dependencies, sitemap) with a stable system prefix
//! first so DeepSeek's automatic prefix caching can apply, caps the context
//! size, caps the model output via `max_tokens`, and only runs on an explicit
//! user action (never in the background).

pub mod client;
pub mod prompt;
pub mod security_prompt;
pub mod workflow_prompt;

pub use client::{AiClientError, DeepSeekClient};
pub use prompt::{
    DependencyEdge, FlowContext, SitemapLine, SummaryPrompt, SummaryStep, build_summary_prompt,
    format_context, format_security_context,
};
pub use security_prompt::{SecurityPrompt, build_security_prompt};
pub use workflow_prompt::{WorkflowPrompt, build_workflow_prompt};
