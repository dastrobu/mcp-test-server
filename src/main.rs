//! Failing MCP Server for Testing Error Handling
//!
//! This server provides a single tool that always fails, useful for testing
//! how MCP clients handle tool execution errors.
//!
//! Built using the official Model Context Protocol Rust SDK.

use rmcp::{
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ErrorCode, ErrorData, Implementation, ServerCapabilities, ServerInfo},
    ServerHandler, ServiceExt,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct FailRequest {}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DelayRequest {
    /// Duration to delay in seconds
    duration_seconds: u64,
}

#[derive(Clone)]
pub struct FailingMcpServer {
    tool_router: ToolRouter<Self>,
}

#[rmcp::tool_router]
impl FailingMcpServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Always returns an error for testing error handling
    #[rmcp::tool(description = "Always returns an error for testing error handling")]
    async fn fail(&self, _params: Parameters<FailRequest>) -> Result<CallToolResult, ErrorData> {
        eprintln!("fail: Returning error");
        Err(ErrorData {
            code: ErrorCode::default(),
            message: "This tool always fails intentionally for testing purposes".into(),
            data: None,
        })
    }

    /// Delays for the specified duration in seconds for timeout testing
    #[rmcp::tool(description = "Delays for the specified duration in seconds for timeout testing")]
    async fn delay(&self, params: Parameters<DelayRequest>) -> Result<CallToolResult, ErrorData> {
        let duration = params.0.duration_seconds;
        eprintln!("delay: Sleeping for {} seconds", duration);
        tokio::time::sleep(tokio::time::Duration::from_secs(duration)).await;
        eprintln!("delay: Completed");
        Ok(CallToolResult::success(vec![]))
    }
}

#[rmcp::tool_handler]
impl ServerHandler for FailingMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "mcp-fail-server".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
            instructions: Some(
                "A test server for analyzing tool error handling in MCP clients. \
                 Provides one tool: 'fail' which always returns an error."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("MCP Fail Server v{} starting", env!("CARGO_PKG_VERSION"));
    eprintln!("Available tools:");
    eprintln!("  - fail: Always returns an error");
    eprintln!("  - delay: Delays for a specified duration (for timeout testing)");
    eprintln!();

    // Create server handler
    let handler = FailingMcpServer::new();

    // Serve on stdio
    let server = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;

    // Wait for completion
    server.waiting().await?;

    Ok(())
}
