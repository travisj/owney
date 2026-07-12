//! IMAP command implementations.
//!
//! This module contains specialized handlers for each IMAP command.
//! For now, most are stubs that will be implemented in future iterations.
//! The READ-ONLY bridge focuses on:
//! - SELECT / EXAMINE (open mailbox)
//! - SEARCH (query)
//! - FETCH (read messages)
//! - LIST (mailbox listing)
//!
//! BLOCKED in perpetuity:
//! - APPEND (send via JMAP only)
//! - STORE (use JMAP Email/set)
//! - DELETE, EXPUNGE (use JMAP Email/set with destroy)
//! - COPY, MOVE (use JMAP Email/set)

// Stub for future expansion
