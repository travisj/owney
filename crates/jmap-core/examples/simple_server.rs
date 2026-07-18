//! A minimal but production-quality JMAP server example.
//!
//! This example demonstrates how to embed jmap-core into a real server:
//! - HTTP listener on localhost:8620
//! - Session discovery at GET /.well-known/jmap
//! - JMAP POST endpoint at /jmap/api
//! - Two simple methods: Ping/ping and Echo/echo
//! - Proper error handling and response codes
//!
//! Run with: cargo run --example simple_server
//! Then:
//!   curl -X GET http://localhost:8620/.well-known/jmap | jq .
//!   curl -X POST http://localhost:8620/jmap/api \
//!     -H 'Content-Type: application/json' \
//!     -d '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Ping/ping",{},"c1"]]}'

use jmap_core::{CORE_CAPABILITY, Dispatcher, Limits};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Minimal request state. In a real server, this might contain
/// the authenticated user, database handles, rate limiters, etc.
#[derive(Debug, Clone)]
struct ServerContext {
    user_id: String,
    #[allow(dead_code)]
    session_id: String,
}

#[tokio::main]
async fn main() {
    // Build the dispatcher with some reasonable limits.
    let mut dispatcher: Dispatcher<ServerContext> = Dispatcher::new("session-1");

    dispatcher = dispatcher.with_limits(Limits {
        max_calls_in_request: 16,
        max_size_request: 10_000_000,
        max_objects_in_get: 500,
        max_objects_in_set: 500,
        max_call_duration: Some(std::time::Duration::from_secs(30)),
        ..Limits::default()
    });

    // Register some methods. In a real server, you'd register
    // Mail/get, Mail/set, Mailbox/query, etc.

    // Ping/ping - Simple "are you alive?" health check.
    dispatcher.register("Ping/ping", CORE_CAPABILITY, |args, _ctx| async move {
        // The args are whatever the client sent (often empty for ping).
        // We just echo back a pong.
        Ok(json!({
            "pong": true,
            "methodArguments": args,
        }))
    });

    // Echo/echo - Mirrors back the request arguments (like Core/echo but custom).
    // Useful for testing.
    dispatcher.register("Echo/echo", CORE_CAPABILITY, |args, ctx| async move {
        Ok(json!({
            "echoedArguments": args,
            "userId": ctx.user_id,
        }))
    });

    // For a real server, you'd register many more methods here:
    // dispatcher.register("Mailbox/get", "urn:ietf:params:jmap:mail", ...);
    // dispatcher.register("Email/query", "urn:ietf:params:jmap:mail", ...);
    // etc.

    // Wrap the dispatcher in Arc<> for sharing across async tasks.
    let dispatcher = Arc::new(dispatcher);

    // Start the HTTP listener on localhost:8620.
    let addr = "127.0.0.1:8620";
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            println!("JMAP server listening on http://{}", addr);
            l
        }
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    loop {
        match listener.accept().await {
            Ok((socket, peer_addr)) => {
                eprintln!("Incoming connection from {}", peer_addr);
                let dispatcher = Arc::clone(&dispatcher);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket, dispatcher).await {
                        eprintln!("Error handling connection from {}: {}", peer_addr, e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}

/// Handle a single TCP connection: HTTP request → response.
///
/// This is a minimal HTTP 1.1 implementation. A real server would use
/// axum, actix, or similar, but this shows the mechanics.
async fn handle_connection(
    socket: tokio::net::TcpStream,
    dispatcher: Arc<Dispatcher<ServerContext>>,
) -> std::io::Result<()> {
    use tokio::io::AsyncBufReadExt;
    use tokio::io::BufReader;

    let (reader, writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = writer;

    // Parse the request line: "GET /path HTTP/1.1"
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim();

    if request_line.is_empty() {
        return Ok(());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return send_response(&mut writer, 400, "Invalid request line").await;
    }

    let method = parts[0];
    let path = parts[1];

    // Parse headers until we hit a blank line.
    // (In a real server, you'd extract auth headers, Content-Type, etc.)
    let mut _headers = BTreeMap::new();
    let mut content_length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let value = v.trim();
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            _headers.insert(key, value.to_string());
        }
    }

    // Read the body if present.
    let mut body = vec![0; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }

    // Route based on method and path.
    match (method, path) {
        ("GET", "/.well-known/jmap") => {
            // Return the session object for discovery.
            match build_session(&dispatcher).await {
                Ok(session) => {
                    let json_body = serde_json::to_string(&session).map_err(|e| {
                        eprintln!("Failed to serialize session: {}", e);
                        std::io::Error::other(e.to_string())
                    })?;
                    send_json_response(&mut writer, 200, &json_body).await?;
                    return Ok(());
                }
                Err(e) => {
                    return send_response(
                        &mut writer,
                        500,
                        &format!("Failed to build session: {}", e),
                    )
                    .await;
                }
            }
        }
        ("POST", "/jmap/api") => {
            // Parse and process the JMAP request.
            match std::str::from_utf8(&body) {
                Ok(body_str) => match serde_json::from_str::<Value>(body_str) {
                    Ok(json_body) => {
                        // Deserialize to a JMAP Request.
                        match serde_json::from_value::<jmap_core::Request>(json_body) {
                            Ok(request) => {
                                // Create a fake context (in a real server, extract from auth headers).
                                let ctx = Arc::new(ServerContext {
                                    user_id: "user123".to_string(),
                                    session_id: "sess456".to_string(),
                                });

                                // Process the request through the dispatcher.
                                match dispatcher.process(request, ctx).await {
                                    Ok(response) => match serde_json::to_string(&response) {
                                        Ok(json_response) => {
                                            send_json_response(&mut writer, 200, &json_response)
                                                .await?;
                                            return Ok(());
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to serialize response: {}", e);
                                            return send_response(
                                                &mut writer,
                                                500,
                                                "Failed to serialize response",
                                            )
                                            .await;
                                        }
                                    },
                                    Err(err) => {
                                        eprintln!("Request processing error: {:?}", err);
                                        let problem = err.problem_details();
                                        let http_status = problem
                                            .get("status")
                                            .and_then(|s| s.as_u64())
                                            .unwrap_or(400)
                                            as u16;
                                        match serde_json::to_string(&problem) {
                                            Ok(json_err) => {
                                                send_json_response(
                                                    &mut writer,
                                                    http_status,
                                                    &json_err,
                                                )
                                                .await?;
                                                return Ok(());
                                            }
                                            Err(e) => {
                                                eprintln!("Failed to serialize error: {}", e);
                                                return send_response(
                                                    &mut writer,
                                                    500,
                                                    "Server error",
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to deserialize JMAP request: {}", e);
                                return send_response(&mut writer, 400, "Invalid JMAP request")
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse JSON body: {}", e);
                        return send_response(&mut writer, 400, "Invalid JSON").await;
                    }
                },
                Err(e) => {
                    eprintln!("Failed to decode body as UTF-8: {}", e);
                    return send_response(&mut writer, 400, "Invalid UTF-8").await;
                }
            }
        }
        _ => return send_response(&mut writer, 404, "Not Found").await,
    }

    #[allow(unreachable_code)]
    Ok(())
}

/// Send a plain-text error response.
async fn send_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    status_code: u16,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        status_code,
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Send a JSON response.
async fn send_json_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    status_code: u16,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status_code,
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Build the RFC 8620 session object to return at /.well-known/jmap.
async fn build_session(
    dispatcher: &Dispatcher<ServerContext>,
) -> Result<jmap_core::Session, String> {
    // In a real server, these might come from configuration or the request.
    let base_url = "http://localhost:8620";
    let username = "demo@example.com";
    let account_id = "u123";

    // Collect the dispatcher's capabilities.
    let capabilities = dispatcher.capabilities().clone();

    // Build and return the session object (RFC 8620 §2).
    Ok(jmap_core::Session::for_account(
        base_url,
        username,
        account_id,
        capabilities,
        "demo-session-state",
    ))
}
