# MCP Test Server

A simple Model Context Protocol (MCP) server that provides various tools to test edge cases with MCP clients. Useful for testing error handling in MCP clients.

## Features

- **fail**: Always returns an error (useful for testing error handling)
- **delay**: Delays response for a specified duration (useful for testing timeouts)
- **succeed**: Always succeeds (useful for verifying basic connectivity)
- **get_image**: Returns an MCP logo image in a specified format (useful for testing image/binary content)
- **get_mixed_content**: Returns a sequence of mixed content items (text and images) in a single response (useful for testing mixed content handling)
- **add_tool**: Dynamically adds a new tool at runtime to session.
- **remove_tool**: Dynamically removes a tool at runtime from session.
- **get_image**: Returns an MCP logo in various image formats (png, gif, jpeg, webp, avif).
- Built with the official [Model Context Protocol Rust SDK](https://github.com/modelcontextprotocol/rust-sdk)
- Communicates over stdio (default) or HTTP (Streamable HTTP) for versatile integration

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

Run the server using stdio (default):

```bash
mcp-test-server
# or
mcp-test-server --transport stdio
```

Run the server using HTTP (Streamable HTTP):

```bash
mcp-test-server --transport http --port 3000
```

The server follows the [Model Context Protocol](https://modelcontextprotocol.io/) specification.

### Available Tools

- **fail**: Always returns an error with the message "This tool always fails intentionally for testing purposes"
- **delay**: Takes `duration_seconds` (integer) and sleeps for that amount of time before returning success.
- **succeed**: Returns a success message immediately.
- **get_image**: Returns an MCP logo image in the specified format. Takes `type` (one of `png`, `gif`, `jpeg`, `webp`, `avif`), and optionally `audience` (array of `user` and/or `assistant`) and `priority` (float from 0.0 to 1.0) for annotations.
- **add_tool**: Adds a dynamic tool. Takes `name` (string) and `input_json_schema` (object).
- **remove_tool**: Removes a dynamic tool. Takes `name` (string).
- **get_image**: Returns an MCP logo image. Takes `type` (enum: png, gif, jpeg, webp, avif) and optional `audience` and `priority`.
- **get_mixed_content**: Returns a sequence of mixed content items in a single response. Takes `content` (array of "text" or "image" values, e.g. `["text", "image", "text"]`). Useful for testing how clients handle multiple content blocks of different types in a single tool response.