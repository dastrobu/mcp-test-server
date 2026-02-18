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
use jsonschema::Validator;

use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "stdio")]
    transport: TransportType,

    #[arg(long, default_value = "3000")]
    port: u16,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
enum TransportType {
    Stdio,
    Http,
}

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

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ValidationResponse {
    valid: bool,
    #[serde(rename = "receivedInput")]
    received_input: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<Vec<String>>,
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

    #[rmcp::tool(
        description = "Adds a dynamic tool. Example input_json_schema: { \"type\": \"object\", \"properties\": { \"city\": { \"type\": \"string\" } } }"
    )]
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
                name: "mcp-test-server".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
            instructions: Some(
                "A test server for analyzing tool execution in MCP clients. \
                 Provides various tools for testing edge cases."
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

#[derive(Clone)]
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
                execution: None,
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
                if e.code == ErrorCode(-32601) || e.code == ErrorCode(-32602) {
                    // MethodNotFound or InvalidParams (tool not found)
                    let name = params.name;
                    let tools = self.inner.dynamic_tools.read().unwrap();
                    if let Some(tool) = tools.get(name.as_ref()) {
                        eprintln!("call_tool: Called dynamic tool '{}'", name);

                        let received_input_value = serde_json::to_value(
                            params.arguments.clone().unwrap_or_default()
                        ).unwrap_or(serde_json::json!({}));

                        // Validate input against schema
                        let schema_value = serde_json::to_value(&tool.input_json_schema)
                            .unwrap_or(serde_json::json!({"type": "object"}));

                        let validation_result = match Validator::new(&schema_value) {
                            Ok(validator) => {
                                let errors: Vec<String> = validator
                                    .iter_errors(&received_input_value)
                                    .map(|e| format!("{}", e))
                                    .collect();

                                if errors.is_empty() {
                                    ValidationResponse {
                                        valid: true,
                                        received_input: received_input_value.clone(),
                                        errors: None,
                                    }
                                } else {
                                    ValidationResponse {
                                        valid: false,
                                        received_input: received_input_value.clone(),
                                        errors: Some(errors),
                                    }
                                }
                            }
                            Err(e) => ValidationResponse {
                                valid: false,
                                received_input: received_input_value.clone(),
                                errors: Some(vec![format!("Schema compilation error: {}", e)]),
                            }
                        };

                        let response_json = serde_json::to_string_pretty(&validation_result)
                            .unwrap_or_else(|_| "{}".to_string());

                        return Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                            response_json,
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
    let cli = Cli::parse();

    // Create server handler
    let handler = FailingMcpServer::new();
    let proxy = DynamicProxy { inner: handler };

    match cli.transport {
        TransportType::Stdio => {
            eprintln!("MCP Fail Server v{} starting", env!("CARGO_PKG_VERSION"));
            eprintln!("Available tools:");
            eprintln!("  - fail: Always returns an error");
            eprintln!("  - delay: Delays for a specified duration (for timeout testing)");
            eprintln!("  - succeed: Always succeeds with a success message");
            eprintln!("  - add_tool: Adds a dynamic tool");
            eprintln!("  - remove_tool: Removes a dynamic tool");
            eprintln!();

            // Serve on stdio
            let server = proxy
                .serve((tokio::io::stdin(), tokio::io::stdout()))
                .await?;

            // Wait for completion
            server.waiting().await?;
        }
        TransportType::Http => {
            run_http(cli.port).await?;
        }
    }

    Ok(())
}

async fn run_http(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let ct = tokio_util::sync::CancellationToken::new();

    let service = StreamableHttpService::new(
        move || {
            let handler = FailingMcpServer::new();
            Ok(DynamicProxy { inner: handler })
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig {
            cancellation_token: ct.child_token(),
            ..Default::default()
        },
    );

    let app = Router::new()
        .nest_service("", service)
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    eprintln!(
        "MCP Fail Server v{} starting on http://{}",
        env!("CARGO_PKG_VERSION"),
        addr
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.unwrap();
            ct.cancel();
        })
        .await?;

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
            result.unwrap_err().code,
            ErrorCode(-32602)
        );
    }

    #[test]
    fn test_validation_response_serialization() {
        // Test valid response
        let valid_response = ValidationResponse {
            valid: true,
            received_input: serde_json::json!({"a": 1, "b": 2}),
            errors: None,
        };

        let json = serde_json::to_value(&valid_response).unwrap();
        assert_eq!(json["valid"], true);
        assert_eq!(json["receivedInput"]["a"], 1);
        assert!(json.get("errors").is_none());

        // Test invalid response with errors
        let invalid_response = ValidationResponse {
            valid: false,
            received_input: serde_json::json!({"a": "wrong"}),
            errors: Some(vec!["error1".to_string(), "error2".to_string()]),
        };

        let json = serde_json::to_value(&invalid_response).unwrap();
        assert_eq!(json["valid"], false);
        assert_eq!(json["receivedInput"]["a"], "wrong");
        assert_eq!(json["errors"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_validation() {
        struct TestCase {
            name: &'static str,
            schema: serde_json::Value,
            input: serde_json::Value,
            should_be_valid: bool,
            expected_error_patterns: Vec<&'static str>,
        }

        let test_cases = vec![
            TestCase {
                name: "valid input with all required fields",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "age": {"type": "number"}
                    },
                    "required": ["name", "age"]
                }),
                input: serde_json::json!({
                    "name": "John",
                    "age": 30
                }),
                should_be_valid: true,
                expected_error_patterns: vec![],
            },
            TestCase {
                name: "missing required field",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "age": {"type": "number"}
                    },
                    "required": ["name", "age"]
                }),
                input: serde_json::json!({
                    "name": "John"
                }),
                should_be_valid: false,
                expected_error_patterns: vec!["age", "required"],
            },
            TestCase {
                name: "wrong type (string instead of number)",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "age": {"type": "number"}
                    }
                }),
                input: serde_json::json!({
                    "name": "John",
                    "age": "thirty"
                }),
                should_be_valid: false,
                expected_error_patterns: vec!["number"],
            },
            TestCase {
                name: "invalid enum value",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "enum": ["add", "subtract", "multiply", "divide"]
                        }
                    },
                    "required": ["operation"]
                }),
                input: serde_json::json!({
                    "operation": "modulo"
                }),
                should_be_valid: false,
                expected_error_patterns: vec!["modulo"],
            },
            TestCase {
                name: "multiple validation errors",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "enum": ["add", "subtract"]
                        },
                        "a": {"type": "number"},
                        "b": {"type": "number"}
                    },
                    "required": ["operation", "a", "b"]
                }),
                input: serde_json::json!({
                    "operation": "power",
                    "a": "not a number"
                }),
                should_be_valid: false,
                expected_error_patterns: vec!["power", "number", "required"],
            },
            TestCase {
                name: "null input when object expected",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    }
                }),
                input: serde_json::json!(null),
                should_be_valid: false,
                expected_error_patterns: vec!["object"],
            },
            TestCase {
                name: "array instead of object",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    }
                }),
                input: serde_json::json!(["not", "an", "object"]),
                should_be_valid: false,
                expected_error_patterns: vec!["object"],
            },
            TestCase {
                name: "number exceeds maximum",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "age": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 120
                        }
                    }
                }),
                input: serde_json::json!({"age": 150}),
                should_be_valid: false,
                expected_error_patterns: vec!["maximum"],
            },
            TestCase {
                name: "number below minimum",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "age": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 120
                        }
                    }
                }),
                input: serde_json::json!({"age": -5}),
                should_be_valid: false,
                expected_error_patterns: vec!["minimum"],
            },
            TestCase {
                name: "number within valid range",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "age": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 120
                        }
                    }
                }),
                input: serde_json::json!({"age": 25}),
                should_be_valid: true,
                expected_error_patterns: vec![],
            },
            TestCase {
                name: "string matches pattern",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "email": {
                            "type": "string",
                            "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
                        }
                    }
                }),
                input: serde_json::json!({"email": "test@example.com"}),
                should_be_valid: true,
                expected_error_patterns: vec![],
            },
            TestCase {
                name: "string does not match pattern",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "email": {
                            "type": "string",
                            "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
                        }
                    }
                }),
                input: serde_json::json!({"email": "not-an-email"}),
                should_be_valid: false,
                expected_error_patterns: vec!["does not match", "not-an-email"],
            },
            TestCase {
                name: "additional properties not allowed",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    },
                    "additionalProperties": false
                }),
                input: serde_json::json!({
                    "name": "John",
                    "extra": "not allowed"
                }),
                should_be_valid: false,
                expected_error_patterns: vec!["additional"],
            },
            TestCase {
                name: "empty input missing required fields",
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    },
                    "required": ["name"]
                }),
                input: serde_json::json!({}),
                should_be_valid: false,
                expected_error_patterns: vec!["name", "required"],
            },
        ];

        for test_case in test_cases {
            let validator = Validator::new(&test_case.schema)
                .unwrap_or_else(|e| panic!("Test '{}': Failed to compile schema: {}", test_case.name, e));

            let errors: Vec<String> = validator
                .iter_errors(&test_case.input)
                .map(|e| format!("{}", e))
                .collect();

            let is_valid = errors.is_empty();

            assert_eq!(
                is_valid, test_case.should_be_valid,
                "Test '{}': Expected valid={}, got valid={}. Errors: {:?}",
                test_case.name, test_case.should_be_valid, is_valid, errors
            );

            if !test_case.should_be_valid {
                for pattern in test_case.expected_error_patterns {
                    assert!(
                        errors.iter().any(|e| e.to_lowercase().contains(&pattern.to_lowercase())),
                        "Test '{}': Expected error containing '{}', but got errors: {:?}",
                        test_case.name, pattern, errors
                    );
                }
            }
        }
    }

    #[test]
    fn test_validation_response_with_complex_input() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string", "format": "email"}
                    },
                    "required": ["name", "email"]
                }
            }
        });

        let validator = Validator::new(&schema).unwrap();

        // Valid nested object
        let valid_input = serde_json::json!({
            "user": {
                "name": "John Doe",
                "email": "john@example.com"
            }
        });

        let errors: Vec<String> = validator
            .iter_errors(&valid_input)
            .map(|e| format!("{}", e))
            .collect();

        assert!(errors.is_empty());
    }

    #[test]
    fn test_invalid_schema_compilation() {
        // Malformed schema - invalid reference
        let bad_schema = serde_json::json!({
            "type": "object",
            "$ref": "#/definitions/nonexistent"
        });

        let result = Validator::new(&bad_schema);
        // Schema compilation should fail or handle the invalid reference
        // The behavior depends on jsonschema crate version
        match result {
            Ok(validator) => {
                // If it compiles, validation should still work
                let input = serde_json::json!({});
                let _errors: Vec<String> = validator
                    .iter_errors(&input)
                    .map(|e| format!("{}", e))
                    .collect();
            }
            Err(_) => {
                // Expected - schema compilation failed
            }
        }
    }

    #[test]
    fn test_validation_response_preserves_input() {
        // Ensure the received input is preserved exactly as received
        let complex_input = serde_json::json!({
            "nested": {
                "array": [1, 2, 3],
                "null_value": null,
                "bool": true,
                "number": 42.5
            },
            "extra": "field"
        });

        let response = ValidationResponse {
            valid: false,
            received_input: complex_input.clone(),
            errors: Some(vec!["test error".to_string()]),
        };

        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized["receivedInput"], complex_input);
        assert_eq!(serialized["valid"], false);
    }

    #[test]
    fn test_empty_schema_validation() {
        // Empty schema allows any input
        let schema = serde_json::json!({});

        let validator = Validator::new(&schema).unwrap();

        let any_input = serde_json::json!({"anything": "goes", "here": [1, 2, 3]});
        let errors: Vec<String> = validator
            .iter_errors(&any_input)
            .map(|e| format!("{}", e))
            .collect();

        assert!(errors.is_empty());
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
            execution: None,
        };

        let json = serde_json::to_string(&tool).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["inputSchema"]["type"], "object");
    }
}
