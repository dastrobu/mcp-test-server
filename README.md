# MCP Test Server

A simple Model Context Protocol (MCP) server that provides various tools to test edge cases with MCP clients. Useful for testing error handling in MCP clients.

## Features

- **fail**: Always returns an error (useful for testing error handling)
- **delay**: Delays response for a specified duration (useful for testing timeouts)
- **succeed**: Always succeeds (useful for verifying basic connectivity)
- **add_tool**: Dynamically adds a new tool at runtime to session.
- **remove_tool**: Dynamically removes a tool at runtime from session.
- **get_image**: Returns an MCP logo image in various formats (png, gif, jpeg, webp, avif)
- Built with the official [MCP Rust SDK](https://github.com/modelcontextprotocol/rust-sdk)
- Communicates over stdio for easy integration

## Installation

```bash
cargo install --git https://github.com/dastrobu/mcp-test-server
```

Or build from source:

```bash
git clone https://github.com/dastrobu/mcp-test-server
cd mcp-test-server
cargo build --release
```

## Usage

Run the server:

```bash
mcp-test-server
```

The server communicates via stdio and follows the [Model Context Protocol](https://modelcontextprotocol.io/) specification.

### Available Tools

- **fail**: Always returns an error with the message "This tool always fails intentionally for testing purposes"
- **delay**: Takes `duration_seconds` (integer) and sleeps for that amount of time before returning success.
- **succeed**: Returns a success message immediately.
- **add_tool**: Adds a dynamic tool. Takes `name` (string) and `input_json_schema` (object).
- **remove_tool**: Removes a dynamic tool. Takes `name` (string).
- **get_image**: Returns an MCP logo image in the specified format. Parameters:
  - `type` (required): Image format - `"png"`, `"gif"`, `"jpeg"`, `"webp"`, or `"avif"`
  - `audience` (optional): Array of intended audiences - `["user"]`, `["assistant"]`, or `["user", "assistant"]`
  - `priority` (optional): Number from 0.0 to 1.0 indicating importance (1.0 = most important, 0.0 = least important)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
