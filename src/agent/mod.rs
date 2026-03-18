// ============================================================
// src/agent/mod.rs
//
// The agentic AI layer — three sub-modules:
//
//   tools.rs  — every security engine wrapped as a Claude tool definition
//               (the schema Claude sees when deciding what to call next)
//
//   client.rs — raw Claude API HTTP client with tool-use support
//               (sends messages, receives tool_use blocks, returns results)
//
//   r#loop.rs — the agentic investigation loop
//               (runs until Claude says stop or max_iterations reached)
//
// Why three files instead of one:
//   Each layer has a single responsibility and can be tested independently.
//   tools.rs has zero I/O. client.rs has zero business logic. loop.rs
//   orchestrates both but owns no JSON schema definitions.
// ============================================================

pub mod client;
pub mod r#loop;
pub mod tools;
