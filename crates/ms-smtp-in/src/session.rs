//! The per-connection SMTP session state machine.
//!
//! Pipelining-correct by construction: every read is drained through the
//! current mode (command parsing or DATA collection) until exhausted, and all
//! generated responses are written in one batch. DATA termination mid-buffer
//! flows straight back into command parsing for the remaining bytes.

use std::net::IpAddr;
use std::sync::Arc;

use smtp_proto::request::receiver::{DataReceiver, RequestReceiver};
use smtp_proto::{Error as SmtpError, Request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{InboundMail, MailHandler, RcptVerdict, SmtpParams};

/// Serve one SMTP connection to completion, including at most one STARTTLS
/// upgrade.
pub async fn serve_connection<H, S>(
    mut stream: S,
    remote: IpAddr,
    params: Arc<SmtpParams>,
    handler: Arc<H>,
) where
    H: MailHandler,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = Session {
        params,
        handler,
        remote,
        mode: Mode::Command,
        helo: String::new(),
        mail_from: None,
        recipients: Vec::new(),
        errors: 0,
        tls_active: false,
    };

    let greeting = format!("220 {} ESMTP ready\r\n", session.params.hostname);
    if stream.write_all(greeting.as_bytes()).await.is_err() {
        return;
    }

    match run_protocol(stream, &mut session).await {
        (_, End::Closed) => {}
        (stream, End::StartTls) => {
            let Some(acceptor) = session.params.tls.clone() else {
                return; // unreachable: StartTls is only returned when configured
            };
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // RFC 3207 §4.2: discard all knowledge gained before TLS.
                    session.helo.clear();
                    session.reset_transaction();
                    session.mode = Mode::Command;
                    session.tls_active = true;
                    // Client speaks first after the handshake (no new banner).
                    run_protocol(tls_stream, &mut session).await;
                }
                Err(err) => {
                    tracing::debug!(%err, %remote, "tls handshake failed");
                }
            }
        }
    }
}

enum End {
    Closed,
    StartTls,
}

/// Run the command/data loop until the connection ends or the client asks to
/// upgrade to TLS. Returns the stream so the caller can wrap it.
async fn run_protocol<H, S>(mut stream: S, session: &mut Session<H>) -> (S, End)
where
    H: MailHandler,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut receiver = RequestReceiver::default();
    let mut buf = vec![0u8; 4096];
    let mut out = Vec::with_capacity(512);

    'connection: loop {
        let read = tokio::time::timeout(session.params.read_timeout, stream.read(&mut buf)).await;
        let n = match read {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break, // socket error
            Err(_) => {
                let _ = stream
                    .write_all(b"421 4.4.2 idle timeout, closing\r\n")
                    .await;
                break;
            }
        };

        let mut iter = buf[..n].iter();
        out.clear();

        // Drain everything we just read through the current mode.
        loop {
            match &mut session.mode {
                Mode::Command => match receiver.ingest(&mut iter) {
                    Ok(request) => {
                        match session.apply(request.into_owned(), &mut out).await {
                            Flow::Continue => {}
                            Flow::Quit => {
                                let _ = stream.write_all(&out).await;
                                break 'connection;
                            }
                            Flow::StartTls => {
                                // Flush the 220 go-ahead, then hand the raw
                                // stream back for the handshake. Any plaintext
                                // bytes already buffered after STARTTLS are
                                // deliberately dropped (plaintext injection
                                // protection).
                                if stream.write_all(&out).await.is_err() {
                                    break 'connection;
                                }
                                return (stream, End::StartTls);
                            }
                        }
                    }
                    Err(SmtpError::NeedsMoreData { .. }) => break,
                    Err(err) => {
                        if !session.protocol_error(err, &mut out) {
                            let _ = stream.write_all(&out).await;
                            break 'connection;
                        }
                    }
                },
                Mode::Data {
                    receiver: data_receiver,
                    data,
                    discarding,
                } => {
                    let done = data_receiver.ingest(&mut iter, data);
                    if *discarding {
                        data.clear();
                    } else if data.len() as u64 > session.params.max_message_size {
                        *discarding = true;
                        data.clear();
                    }
                    if done {
                        session.finish_data(&mut out).await;
                    } else {
                        break; // need more bytes from the socket
                    }
                }
            }
        }

        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            break;
        }
    }

    (stream, End::Closed)
}

enum Mode {
    Command,
    Data {
        receiver: DataReceiver,
        data: Vec<u8>,
        discarding: bool,
    },
}

enum Flow {
    Continue,
    Quit,
    StartTls,
}

struct Session<H> {
    params: Arc<SmtpParams>,
    handler: Arc<H>,
    remote: IpAddr,
    mode: Mode,
    helo: String,
    mail_from: Option<String>,
    recipients: Vec<String>,
    errors: usize,
    tls_active: bool,
}

impl<H: MailHandler> Session<H> {
    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
    }

    async fn apply(&mut self, request: Request<String>, out: &mut Vec<u8>) -> Flow {
        match request {
            Request::Ehlo { host } => {
                self.helo = host;
                self.reset_transaction();
                let hostname = &self.params.hostname;
                let size = self.params.max_message_size;
                let starttls = if self.params.tls.is_some() && !self.tls_active {
                    "250-STARTTLS\r\n"
                } else {
                    ""
                };
                out.extend_from_slice(
                    format!(
                        "250-{hostname} greets you\r\n250-PIPELINING\r\n250-SIZE {size}\r\n\
                         {starttls}250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250 SMTPUTF8\r\n"
                    )
                    .as_bytes(),
                );
            }
            Request::Helo { host } => {
                self.helo = host;
                self.reset_transaction();
                out.extend_from_slice(format!("250 {}\r\n", self.params.hostname).as_bytes());
            }
            Request::Mail { from } => {
                if self.mail_from.is_some() {
                    reply(out, "503 5.5.1 nested MAIL command");
                } else if from.size != 0 && from.size as u64 > self.params.max_message_size {
                    reply(out, "552 5.3.4 message size exceeds limit");
                } else {
                    self.mail_from = Some(from.address);
                    reply(out, "250 2.1.0 OK");
                }
            }
            Request::Rcpt { to } => {
                if self.mail_from.is_none() {
                    reply(out, "503 5.5.1 MAIL first");
                } else if self.recipients.len() >= self.params.max_recipients {
                    reply(out, "452 4.5.3 too many recipients");
                } else {
                    match self.handler.rcpt(&to.address).await {
                        RcptVerdict::Accept => {
                            self.recipients.push(to.address);
                            reply(out, "250 2.1.5 OK");
                        }
                        RcptVerdict::UnknownUser => {
                            reply(out, "550 5.1.1 no such user here");
                        }
                        RcptVerdict::NotLocal => {
                            reply(out, "550 5.7.1 relaying denied");
                        }
                        RcptVerdict::TryAgainLater => {
                            reply(out, "451 4.3.0 temporary lookup failure, try again");
                        }
                    }
                }
            }
            Request::Data => {
                if self.recipients.is_empty() {
                    reply(out, "503 5.5.1 RCPT first");
                } else {
                    reply(out, "354 go ahead, end with <CRLF>.<CRLF>");
                    self.mode = Mode::Data {
                        receiver: DataReceiver::new(),
                        data: Vec::with_capacity(16 * 1024),
                        discarding: false,
                    };
                }
            }
            Request::Rset => {
                self.reset_transaction();
                reply(out, "250 2.0.0 OK");
            }
            Request::Noop { .. } => reply(out, "250 2.0.0 OK"),
            Request::Quit => {
                reply(out, "221 2.0.0 bye");
                return Flow::Quit;
            }
            Request::Vrfy { .. } | Request::Expn { .. } => {
                reply(out, "252 2.5.2 cannot verify, send some mail and find out");
            }
            Request::StartTls => {
                if self.tls_active {
                    reply(out, "503 5.5.1 already in TLS");
                } else if self.params.tls.is_some() {
                    reply(out, "220 2.0.0 ready to start TLS");
                    return Flow::StartTls;
                } else {
                    reply(out, "502 5.5.1 STARTTLS not available");
                }
            }
            Request::Auth { .. } => reply(out, "503 5.5.1 no auth on this port"),
            Request::Bdat { .. }
            | Request::Lhlo { .. }
            | Request::Help { .. }
            | Request::Etrn { .. }
            | Request::Atrn { .. }
            | Request::Burl { .. } => reply(out, "502 5.5.1 command not implemented"),
        }
        Flow::Continue
    }

    /// Handle a command-parse error. Returns false when the connection should
    /// be dropped for abuse.
    fn protocol_error(&mut self, err: SmtpError, out: &mut Vec<u8>) -> bool {
        self.errors += 1;
        if self.errors >= self.params.max_errors {
            reply(out, "421 4.7.0 too many errors, closing");
            return false;
        }
        match err {
            SmtpError::UnknownCommand => reply(out, "500 5.5.2 command not recognized"),
            SmtpError::InvalidSenderAddress => reply(out, "501 5.1.7 invalid sender address"),
            SmtpError::InvalidRecipientAddress => {
                reply(out, "501 5.1.3 invalid recipient address");
            }
            _ => reply(out, "501 5.5.4 syntax error"),
        }
        true
    }

    async fn finish_data(&mut self, out: &mut Vec<u8>) {
        let Mode::Data {
            data, discarding, ..
        } = std::mem::replace(&mut self.mode, Mode::Command)
        else {
            reply(out, "451 4.3.0 internal error");
            return;
        };

        if discarding {
            self.reset_transaction();
            reply(out, "552 5.3.4 message size exceeds limit");
            return;
        }

        let mut raw = self.received_header().into_bytes();
        raw.extend_from_slice(&data);
        // DataReceiver strips the CRLF that preceded the terminating dot.
        raw.extend_from_slice(b"\r\n");

        let mail = InboundMail {
            remote: self.remote,
            helo: self.helo.clone(),
            mail_from: self.mail_from.take().unwrap_or_default(),
            recipients: std::mem::take(&mut self.recipients),
            raw,
        };
        match self.handler.deliver(mail).await {
            Ok(()) => reply(out, "250 2.0.0 accepted for delivery"),
            Err(err) => {
                tracing::warn!(%err, "delivery failed");
                reply(out, "451 4.3.0 temporary delivery failure, try again");
            }
        }
    }

    /// Trace header prepended to every accepted message (RFC 5321 §4.4).
    fn received_header(&self) -> String {
        let helo = if self.helo.is_empty() {
            "unknown"
        } else {
            &self.helo
        };
        format!(
            "Received: from {helo} ([{remote}])\r\n\tby {hostname} with {protocol};\r\n\t{date}\r\n",
            remote = self.remote,
            hostname = self.params.hostname,
            protocol = if self.tls_active { "ESMTPS" } else { "ESMTP" },
            date = ms_core::time::rfc2822_utc(unix_now()),
        )
    }
}

fn reply(out: &mut Vec<u8>, line: &str) {
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(b"\r\n");
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
