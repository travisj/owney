//! Full-text search index management via tantivy.
//! One index per account, stored at $DATA_DIR/search/{account_id}.

use std::path::PathBuf;
use std::sync::Arc;

use owney_core::EmailId;
use owney_search::{IndexReader, IndexWriter, SearchError, SearchResult};
use tokio::sync::RwLock;

/// Per-account search index manager. Wraps IndexWriter/IndexReader for thread-safe access.
#[derive(Debug)]
pub struct SearchIndex {
    index_path: PathBuf,
    writer: Arc<RwLock<Option<IndexWriter>>>,
}

impl SearchIndex {
    /// Create a new search index manager for an account.
    pub fn new(index_path: PathBuf) -> Self {
        Self {
            index_path,
            writer: Arc::new(RwLock::new(None)),
        }
    }

    /// Lazy-initialize the index writer on first write.
    async fn get_writer(&self) -> Result<Arc<RwLock<Option<IndexWriter>>>, SearchError> {
        let mut guard = self.writer.write().await;
        if guard.is_none() {
            *guard = Some(IndexWriter::open(self.index_path.clone())?);
        }
        Ok(self.writer.clone())
    }

    /// Index an email document (async, non-blocking).
    /// Fails gracefully if index is unavailable; caller should log and continue.
    pub async fn index_email(
        &self,
        email_id: EmailId,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), SearchError> {
        let writer_arc = self.get_writer().await?;
        let mut writer_guard = writer_arc.write().await;
        if let Some(ref mut writer) = *writer_guard {
            writer
                .index_email(email_id, from, to, subject, body)
                .await?;
            writer.commit().await?;
        }
        Ok(())
    }

    /// Delete an email from the index (async, non-blocking).
    pub async fn delete_email(&self, email_id: EmailId) -> Result<(), SearchError> {
        let writer_arc = self.get_writer().await?;
        let mut writer_guard = writer_arc.write().await;
        if let Some(ref mut writer) = *writer_guard {
            writer.delete_email(email_id).await?;
            writer.commit().await?;
        }
        Ok(())
    }

    /// Search for emails matching the query text with BM25 scoring.
    pub async fn search(
        &self,
        query_text: &str,
        limit: usize,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let reader = IndexReader::open(self.index_path.clone())?;
        reader.search(query_text, limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn index_and_search_async() {
        let dir = TempDir::new().expect("tempdir");
        let index = SearchIndex::new(dir.path().to_path_buf());

        let email_id = EmailId::new();
        index
            .index_email(
                email_id,
                "alice@example.com",
                "bob@example.com",
                "Test Subject",
                "Important email body",
            )
            .await
            .expect("index");

        let results = index.search("important", 10).await.expect("search");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].email_id, email_id);
        assert!(results[0].score > 0.0);
    }

    #[tokio::test]
    async fn delete_email_removes_from_index() {
        let dir = TempDir::new().expect("tempdir");
        let index = SearchIndex::new(dir.path().to_path_buf());

        let email_id = EmailId::new();
        index
            .index_email(
                email_id,
                "alice@example.com",
                "bob@example.com",
                "Delete Me",
                "remove this",
            )
            .await
            .expect("index");

        index.delete_email(email_id).await.expect("delete");

        let results = index.search("delete", 10).await.expect("search");
        assert!(results.is_empty());
    }
}
