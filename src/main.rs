//! Failing MCP Server for Testing Error Handling
//!
//! This server provides a single tool that always fails, useful for testing
//! how MCP clients handle tool execution errors.
//!
//! Built using the official Model Context Protocol Rust SDK.

use rmcp::service::RequestContext;
use rmcp::service::RoleServer;
use rmcp::{
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResult, ErrorCode, ErrorData, Implementation,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
        ServerNotification, ToolListChangedNotification,
    },
    ServerHandler, ServiceExt,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct FailRequest {}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DelayRequest {
    /// Duration to delay in seconds
    duration_seconds: u64,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct SucceedRequest {}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AddToolRequest {
    name: String,
    input_json_schema: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct RemoveToolRequest {
    name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolDefinition {
    name: String,
    input_json_schema: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone)]
pub struct FailingMcpServer {
    tool_router: ToolRouter<Self>,
    pub dynamic_tools: Arc<RwLock<HashMap<String, ToolDefinition>>>,
}

#[rmcp::tool_router]
impl FailingMcpServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            dynamic_tools: Arc::new(RwLock::new(HashMap::new())),
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

    /// Always succeeds with a success message for testing successful tool execution
    #[rmcp::tool(
        description = "Always succeeds with a success message for testing successful tool execution"
    )]
    async fn succeed(
        &self,
        _params: Parameters<SucceedRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        eprintln!("succeed: Returning success");
        Ok(CallToolResult::success(vec![]))
    }

    #[rmcp::tool(description = "Adds a dynamic tool")]
    async fn add_tool(
        &self,
        params: Parameters<AddToolRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = params.0.name.clone();
        let schema = params.0.input_json_schema.clone();

        if let Some(t) = schema.get("type") {
            if t != "object" {
                return Err(ErrorData {
                    code: ErrorCode(-32602),
                    message: "input_json_schema must be of type 'object'".into(),
                    data: None,
                });
            }
        } else {
            return Err(ErrorData {
                code: ErrorCode(-32602),
                message: "input_json_schema must have 'type': 'object'".into(),
                data: None,
            });
        }

        {
            let mut tools = self.dynamic_tools.write().unwrap();
            tools.insert(
                name.clone(),
                ToolDefinition {
                    name,
                    input_json_schema: schema,
                },
            );
        }

        eprintln!("add_tool: Added tool '{}'", params.0.name);

        Ok(CallToolResult::success(vec![rmcp::model::Content::text(
            "got input...",
        )]))
    }

    #[rmcp::tool(description = "Removes a dynamic tool")]
    async fn remove_tool(
        &self,
        params: Parameters<RemoveToolRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = params.0.name.clone();
        {
            let mut tools = self.dynamic_tools.write().unwrap();
            tools.remove(&name);
        }

        eprintln!("remove_tool: Removed tool '{}'", name);

        Ok(CallToolResult::success(vec![rmcp::model::Content::text(
            "tool removed",
        )]))
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
            capabilities: {
                let mut caps = ServerCapabilities::builder().enable_tools().build();
                if let Some(tools) = &mut caps.tools {
                    tools.list_changed = Some(true);
                }
                caps
            },
            ..Default::default()
        }
    }
}

struct DynamicProxy {
    inner: FailingMcpServer,
}

impl ServerHandler for DynamicProxy {
    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    async fn list_tools(
        &self,
        params: Option<PaginatedRequestParams>,
        req: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        // Get static tools from inner
        let mut result = self.inner.list_tools(params, req).await?;

        // Add dynamic tools
        let dynamic = self.inner.dynamic_tools.read().unwrap();
        for tool in dynamic.values() {
            let input_schema = Arc::new(tool.input_json_schema.clone());

            result.tools.push(rmcp::model::Tool {
                name: tool.name.clone().into(),
                description: Some("Dynamic tool".into()),
                input_schema,
                output_schema: None,
                title: None,
                annotations: None,
                icons: None,
                meta: None,
            });
        }

        Ok(result)
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        req: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = params.name.clone();
        let req_clone = req.clone();

        // Try inner first
        let result = self.inner.call_tool(params.clone(), req).await;

        match result {
            Ok(res) => {
                if name == "add_tool" || name == "remove_tool" {
                    eprintln!("Sending tools/list_changed notification");
                    if let Err(e) = req_clone
                        .peer
                        .send_notification(ServerNotification::ToolListChangedNotification(
                            ToolListChangedNotification::default(),
                        ))
                        .await
                    {
                        eprintln!("Failed to send notification: {:?}", e);
                    }
                }
                Ok(res)
            }
            Err(e) => {
                if e.code == ErrorCode(-32601) {
                    // MethodNotFound
                    let name = params.name;
                    let tools = self.inner.dynamic_tools.read().unwrap();
                    if let Some(_tool) = tools.get(name.as_ref()) {
                        eprintln!("call_tool: Called dynamic tool '{}'", name);
                        return Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                            "got input...",
                        )]));
                    }
                }
                Err(e)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("MCP Fail Server v{} starting", env!("CARGO_PKG_VERSION"));
    eprintln!("Available tools:");
    eprintln!("  - fail: Always returns an error");
    eprintln!("  - delay: Delays for a specified duration (for timeout testing)");
    eprintln!("  - succeed: Always succeeds with a success message");
    eprintln!("  - add_tool: Adds a dynamic tool");
    eprintln!("  - remove_tool: Removes a dynamic tool");
    eprintln!();

    // Create server handler
    let handler = FailingMcpServer::new();
    let proxy = DynamicProxy { inner: handler };

    // Serve on stdio
    let server = proxy
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;

    // Wait for completion
    server.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dynamic_tools() {
        let server = FailingMcpServer::new();

        // Test add_tool success
        let add_params = AddToolRequest {
            name: "my_dynamic_tool".into(),
            input_json_schema: serde_json::json!({"type": "object"})
                .as_object()
                .unwrap()
                .clone(),
        };

        let result = server.add_tool(Parameters(add_params)).await;
        assert!(result.is_ok());

        {
            let tools = server.dynamic_tools.read().unwrap();
            assert!(tools.contains_key("my_dynamic_tool"));
            assert_eq!(
                tools.get("my_dynamic_tool").unwrap().name,
                "my_dynamic_tool"
            );
        }

        // Test remove_tool
        let remove_params = RemoveToolRequest {
            name: "my_dynamic_tool".into(),
        };

        let result = server.remove_tool(Parameters(remove_params)).await;
        assert!(result.is_ok());

        {
            let tools = server.dynamic_tools.read().unwrap();
            assert!(!tools.contains_key("my_dynamic_tool"));
        }
    }

    #[tokio::test]
    async fn test_add_tool_validation() {
        let server = FailingMcpServer::new();

        // Test add_tool with invalid type
        let add_params = AddToolRequest {
            name: "invalid_tool".into(),
            input_json_schema: serde_json::json!({"type": "string"})
                .as_object()
                .unwrap()
                .clone(),
        };

        let result = server.add_tool(Parameters(add_params)).await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().message,
            "input_json_schema must be of type 'object'"
        );

        // Test add_tool with missing type
        let add_params_missing = AddToolRequest {
            name: "missing_type_tool".into(),
            input_json_schema: serde_json::json!({"properties": {}})
                .as_object()
                .unwrap()
                .clone(),
        };

        let result = server.add_tool(Parameters(add_params_missing)).await;
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().message,
            "input_json_schema must have 'type': 'object'"
        );
    }

    #[test]
    fn test_tool_serialization_schema() {
        // Verify that a correct schema serializes with type: object
        let schema = serde_json::json!({"type": "object"})
            .as_object()
            .unwrap()
            .clone();

        let tool = rmcp::model::Tool {
            name: "test".into(),
            description: Some("Dynamic tool".into()),
            input_schema: Arc::new(schema),
            output_schema: None,
            title: None,
            annotations: None,
            icons: None,
            meta: None,
        };

        let json = serde_json::to_string(&tool).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["inputSchema"]["type"], "object");
    }
}
