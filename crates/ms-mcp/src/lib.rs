//! Model Context Protocol server (2025-06-18 revision).
//!
//! MCP is JSON-RPC 2.0. This crate implements the protocol methods
//! (`initialize`, `tools/list`, `tools/call`) and the mailbox tool set,
//! transport-agnostic: [`handle`] takes one JSON-RPC message and returns the
//! response, so it drops onto axum (streamable HTTP) or a stdio loop equally.

pub mod service;

use serde_json::{Value, json};

pub use service::{McpCtx, ServiceError};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// The tool catalog advertised to agents.
pub fn tools() -> Value {
    json!([
        tool(
            "list_mailboxes",
            "List the account's mailboxes with unread counts.",
            json!({"type": "object", "properties": {}})
        ),
        tool(
            "search_email",
            "List recent emails, optionally within one mailbox role (inbox, screener, sent, archive, junk).",
            json!({"type": "object", "properties": {
                "mailbox": {"type": "string", "description": "role: inbox|screener|sent|archive|junk|trash"},
                "limit": {"type": "integer", "default": 20},
            }})
        ),
        tool(
            "get_email",
            "Fetch one email's full body, keywords, and AI annotations.",
            json!({"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]})
        ),
        tool(
            "get_thread",
            "Fetch all emails in a thread.",
            json!({"type": "object", "properties": {"threadId": {"type": "string"}}, "required": ["threadId"]})
        ),
        tool(
            "move_email",
            "Move an email to a mailbox role (archive, junk, trash, inbox, screener). Undoable.",
            json!({"type": "object", "properties": {
                "id": {"type": "string"}, "mailbox": {"type": "string"},
            }, "required": ["id", "mailbox"]})
        ),
        tool(
            "mark_read",
            "Mark an email read or unread.",
            json!({"type": "object", "properties": {
                "id": {"type": "string"}, "read": {"type": "boolean", "default": true},
            }, "required": ["id"]})
        ),
        tool(
            "summarize_thread",
            "Summarize a thread from its stored AI annotations.",
            json!({"type": "object", "properties": {"threadId": {"type": "string"}}, "required": ["threadId"]})
        ),
        tool(
            "create_draft",
            "Create a draft email in the Drafts mailbox (does not send).",
            json!({"type": "object", "properties": {
                "to": {"type": "array", "items": {"type": "string"}},
                "subject": {"type": "string"}, "body": {"type": "string"},
            }, "required": ["to", "subject", "body"]})
        ),
        tool(
            "send_email",
            "Send an email now (requires a send-scoped token).",
            json!({"type": "object", "properties": {
                "to": {"type": "array", "items": {"type": "string"}},
                "subject": {"type": "string"}, "body": {"type": "string"},
            }, "required": ["to", "subject", "body"]})
        ),
        tool(
            "get_ai_activity",
            "List recent AI actions taken on this mailbox, each with an undoable flag.",
            json!({"type": "object", "properties": {"limit": {"type": "integer", "default": 20}}})
        ),
        tool(
            "undo_action",
            "Undo an AI or agent action by id (from get_ai_activity).",
            json!({"type": "object", "properties": {"actionId": {"type": "string"}}, "required": ["actionId"]})
        ),
    ])
}

fn tool(name: &str, description: &str, schema: Value) -> Value {
    json!({"name": name, "description": description, "inputSchema": schema})
}

/// Handle one JSON-RPC request. Returns `None` for notifications (no id).
pub async fn handle(ctx: &McpCtx, request: &Value) -> Option<Value> {
    let id = request.get("id").cloned()?;
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(json!({}));

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "mailserver", "version": env!("CARGO_PKG_VERSION")},
        })),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => call_tool(ctx, &params).await,
        "ping" => Ok(json!({})),
        other => Err(rpc_error(-32601, &format!("method not found: {other}"))),
    };

    Some(match result {
        Ok(value) => json!({"jsonrpc": "2.0", "id": id, "result": value}),
        Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
    })
}

async fn call_tool(ctx: &McpCtx, params: &Value) -> Result<Value, Value> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let outcome = dispatch(ctx, name, &args).await;
    match outcome {
        Ok(value) => Ok(json!({
            "content": [{"type": "text", "text": value.to_string()}],
            "isError": false,
        })),
        // Tool errors are reported in-band (isError), not as protocol errors,
        // so the agent can see and react to them.
        Err(ServiceError::Invalid(msg)) | Err(ServiceError::Forbidden(msg)) => Ok(json!({
            "content": [{"type": "text", "text": msg}],
            "isError": true,
        })),
        Err(ServiceError::Storage(err)) => Err(rpc_error(-32603, &err.to_string())),
    }
}

async fn dispatch(ctx: &McpCtx, name: &str, args: &Value) -> Result<Value, ServiceError> {
    let str_arg = |key: &str| args.get(key).and_then(Value::as_str).map(str::to_owned);
    let list_arg = |key: &str| {
        args.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let usize_arg = |key: &str, default: usize| {
        args.get(key)
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(default)
    };
    let require = |value: Option<String>, key: &str| {
        value.ok_or_else(|| ServiceError::Invalid(format!("missing required argument {key}")))
    };

    match name {
        "list_mailboxes" => ctx.list_mailboxes().await,
        "search_email" => {
            ctx.search(str_arg("mailbox").as_deref(), usize_arg("limit", 20))
                .await
        }
        "get_email" => ctx.get_email(&require(str_arg("id"), "id")?).await,
        "get_thread" => {
            ctx.get_thread(&require(str_arg("threadId"), "threadId")?)
                .await
        }
        "move_email" => {
            ctx.move_email(
                &require(str_arg("id"), "id")?,
                &require(str_arg("mailbox"), "mailbox")?,
            )
            .await
        }
        "mark_read" => {
            let read = args.get("read").and_then(Value::as_bool).unwrap_or(true);
            ctx.set_keyword(&require(str_arg("id"), "id")?, "$seen", read)
                .await
        }
        "summarize_thread" => {
            ctx.summarize_thread(&require(str_arg("threadId"), "threadId")?)
                .await
        }
        "create_draft" => {
            ctx.create_draft(
                &list_arg("to"),
                &require(str_arg("subject"), "subject")?,
                &require(str_arg("body"), "body")?,
            )
            .await
        }
        "send_email" => {
            ctx.send_email(
                &list_arg("to"),
                &require(str_arg("subject"), "subject")?,
                &require(str_arg("body"), "body")?,
            )
            .await
        }
        "get_ai_activity" => ctx.get_ai_activity(usize_arg("limit", 20)).await,
        "undo_action" => {
            ctx.undo_action(&require(str_arg("actionId"), "actionId")?)
                .await
        }
        other => Err(ServiceError::Invalid(format!("unknown tool {other}"))),
    }
}

fn rpc_error(code: i64, message: &str) -> Value {
    json!({"code": code, "message": message})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_catalog_is_well_formed() {
        let tools = tools();
        let list = tools.as_array().expect("array");
        assert!(list.len() >= 11);
        for tool in list {
            assert!(tool["name"].is_string(), "{tool}");
            assert!(tool["description"].is_string(), "{tool}");
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        }
        assert!(list.iter().any(|t| t["name"] == "send_email"));
    }
}
