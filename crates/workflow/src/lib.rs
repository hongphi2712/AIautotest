//! Workflow engine: strict contract, graph/dataflow validation and an
//! edge-driven execution engine. AI generation (in `api-tester-ai`) produces
//! workflows against this contract; the server wires validation, a bounded
//! repair loop, preview/approve and execution.

pub mod contract;
pub mod exec;
pub mod jsonpath;
pub mod validation;

pub use contract::{Edge, LoopConfig, Node, NodeKind, Workflow};
pub use exec::{
    NodeEvent, NodeResult, RunResult, RunState, RunStatus, WorkflowError, WorkflowRunner,
};
pub use validation::{ScopeWarning, Validation, validate};
