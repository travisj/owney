//! SQLite behind a dedicated writer thread.
//!
//! SQLite allows one writer at a time; instead of a connection pool fighting
//! over a write lock, all access goes through a single thread that owns the
//! connection, fed by an async channel. Callers submit closures and await the
//! result. Read-only connection pooling can be added later without changing
//! this interface.

use std::path::Path;
use std::thread::JoinHandle;

use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

use crate::error::StorageError;
use crate::migrations;

type Job = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

#[derive(Debug)]
pub struct Db {
    tx: mpsc::Sender<Job>,
    handle: Option<JoinHandle<()>>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        migrations::apply(&mut conn)?;

        let (tx, mut rx) = mpsc::channel::<Job>(256);
        let handle = std::thread::Builder::new()
            .name("sqlite-writer".to_owned())
            .spawn(move || {
                while let Some(job) = rx.blocking_recv() {
                    job(&mut conn);
                }
                // Flush the WAL on clean shutdown; ignore failure, WAL recovery handles it.
                let _ = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
            })
            .map_err(|source| StorageError::io(path, source))?;

        Ok(Self {
            tx,
            handle: Some(handle),
        })
    }

    /// Run `f` on the writer thread and await its result.
    pub async fn call<T, F>(&self, f: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        let job: Job = Box::new(move |conn| {
            let _ = reply_tx.send(f(conn));
        });
        self.tx.send(job).await.map_err(|_| StorageError::Closed)?;
        reply_rx.await.map_err(|_| StorageError::Closed)?
    }

    /// Shut down the writer thread, checkpointing the WAL.
    pub fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        // Replace the sender so the channel closes and the thread drains + exits.
        let (dead_tx, _) = mpsc::channel(1);
        let tx = std::mem::replace(&mut self.tx, dead_tx);
        drop(tx);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn call_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Db::open(&dir.path().join("test.db")).expect("open");

        let value: i64 = db
            .call(|conn| Ok(conn.query_row("SELECT 40 + 2", [], |row| row.get(0))?))
            .await
            .expect("query");
        assert_eq!(value, 42);
        db.close();
    }

    #[tokio::test]
    async fn many_concurrent_calls_serialize_safely() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = std::sync::Arc::new(Db::open(&dir.path().join("test.db")).expect("open"));

        db.call(|conn| {
            conn.execute_batch("CREATE TABLE t (n INTEGER)")?;
            Ok(())
        })
        .await
        .expect("create");

        let mut joins = Vec::new();
        for n in 0..100i64 {
            let db = db.clone();
            joins.push(tokio::spawn(async move {
                db.call(move |conn| {
                    conn.execute("INSERT INTO t (n) VALUES (?1)", [n])?;
                    Ok(())
                })
                .await
            }));
        }
        for join in joins {
            join.await.expect("join").expect("insert");
        }

        let count: i64 = db
            .call(|conn| Ok(conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0))?))
            .await
            .expect("count");
        assert_eq!(count, 100);
    }
}
