//! Full-text search via tantivy. One index per account, stored at $DATA_DIR/search/{account_id}.
//!
//! IndexWriter adds/updates documents on email ingest/deletion.
//! IndexReader queries the index for text search.

use owney_core::EmailId;
use std::path::PathBuf;
use tantivy::schema::*;
use tantivy::{Document, Index, IndexWriter as TantivyWriter};

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("tantivy: {0}")]
    Tantivy(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("index not ready: {0}")]
    NotReady(String),
}

/// Search result with BM25 score for ranking.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub email_id: EmailId,
    pub score: f32,
}

/// Look up a schema field that `email_schema` is expected to have defined.
fn field(schema: &Schema, name: &str) -> Result<Field, SearchError> {
    schema
        .get_field(name)
        .ok_or_else(|| SearchError::Tantivy(format!("schema missing field {name}")))
}

/// Schema: email_id (primary key), from, to, subject, body (full-text).
fn email_schema() -> Schema {
    let mut schema_builder = Schema::builder();
    schema_builder.add_text_field("email_id", STRING | STORED);
    schema_builder.add_text_field("from", TEXT | STORED);
    schema_builder.add_text_field("to", TEXT | STORED);
    schema_builder.add_text_field("subject", TEXT | STORED);
    schema_builder.add_text_field("body", TEXT | STORED);
    schema_builder.build()
}

/// IndexWriter: add/update/delete documents in the index.
pub struct IndexWriter {
    index: Index,
    writer: TantivyWriter,
}

impl std::fmt::Debug for IndexWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexWriter").finish()
    }
}

impl IndexWriter {
    /// Open or create an index at the given path.
    pub fn open(index_path: PathBuf) -> Result<Self, SearchError> {
        std::fs::create_dir_all(&index_path).map_err(|e| {
            SearchError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to create index dir {}: {}", index_path.display(), e),
            ))
        })?;

        let schema = email_schema();
        let index = Index::open_in_dir(&index_path)
            .or_else(|_| Index::create_in_dir(&index_path, schema))
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        let writer = index
            .writer(50_000_000) // 50MB buffer
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        Ok(Self { index, writer })
    }

    /// Add or update an email document in the index.
    pub async fn index_email(
        &mut self,
        email_id: EmailId,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), SearchError> {
        let schema = self.index.schema();
        let mut doc = Document::new();

        doc.add_text(field(&schema, "email_id")?, email_id.to_string());
        doc.add_text(field(&schema, "from")?, from);
        doc.add_text(field(&schema, "to")?, to);
        doc.add_text(field(&schema, "subject")?, subject);
        doc.add_text(field(&schema, "body")?, body);

        self.writer
            .add_document(doc)
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        Ok(())
    }

    /// Delete an email from the index.
    pub async fn delete_email(&mut self, email_id: EmailId) -> Result<(), SearchError> {
        let schema = self.index.schema();
        let query =
            tantivy::query::QueryParser::for_index(&self.index, vec![field(&schema, "email_id")?])
                .parse_query(&email_id.to_string())
                .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        self.writer
            .delete_query(Box::new(query))
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        Ok(())
    }

    /// Commit pending changes to the index.
    pub async fn commit(&mut self) -> Result<(), SearchError> {
        self.writer
            .commit()
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;
        Ok(())
    }
}

/// IndexReader: query the index for text search.
pub struct IndexReader {
    index: Index,
}

impl std::fmt::Debug for IndexReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexReader").finish()
    }
}

impl IndexReader {
    /// Open an existing index at the given path.
    pub fn open(index_path: PathBuf) -> Result<Self, SearchError> {
        let index =
            Index::open_in_dir(&index_path).map_err(|e| SearchError::Tantivy(e.to_string()))?;
        Ok(Self { index })
    }

    /// Search for emails matching the query text with BM25 scoring.
    /// Returns ranked results with relevance scores (higher = more relevant).
    pub async fn search(
        &self,
        query_text: &str,
        limit: usize,
    ) -> Result<Vec<SearchResult>, SearchError> {
        let schema = self.index.schema();
        let reader = self
            .index
            .reader()
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        let searcher = reader.searcher();
        let query_parser = tantivy::query::QueryParser::for_index(
            &self.index,
            vec![
                field(&schema, "subject")?,
                field(&schema, "body")?,
                field(&schema, "from")?,
                field(&schema, "to")?,
            ],
        );

        let query = query_parser
            .parse_query(query_text)
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        let top_docs = searcher
            .search(&query, &tantivy::collector::TopDocs::with_limit(limit))
            .map_err(|e| SearchError::Tantivy(e.to_string()))?;

        let email_id_field = field(&schema, "email_id")?;
        let mut results = Vec::new();
        for (score, doc_address) in top_docs {
            if let Ok(doc) = searcher.doc(doc_address)
                && let Some(email_id_val) = doc.get_first(email_id_field)
                && let Some(email_id_str) = email_id_val.as_text()
                && let Ok(email_id) = email_id_str.parse()
            {
                results.push(SearchResult { email_id, score });
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn index_and_search() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer = IndexWriter::open(dir.path().to_path_buf()).expect("open writer");

        let email_id = EmailId::new();
        writer
            .index_email(
                email_id,
                "alice@example.com",
                "bob@example.com",
                "Test Subject",
                "This is a test email body with important information.",
            )
            .await
            .expect("index");
        writer.commit().await.expect("commit");

        let reader = IndexReader::open(dir.path().to_path_buf()).expect("open reader");
        let results = reader.search("test", 10).await.expect("search");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].email_id, email_id);
        assert!(results[0].score > 0.0);
    }

    #[tokio::test]
    async fn search_multiple_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer = IndexWriter::open(dir.path().to_path_buf()).expect("open writer");

        let id1 = EmailId::new();
        let id2 = EmailId::new();

        writer
            .index_email(
                id1,
                "alice@example.com",
                "bob@example.com",
                "Budget Report",
                "Q1 financials",
            )
            .await
            .expect("index 1");
        writer
            .index_email(
                id2,
                "alice@example.com",
                "eve@example.com",
                "Meeting Notes",
                "Team standup at 2pm",
            )
            .await
            .expect("index 2");
        writer.commit().await.expect("commit");

        let reader = IndexReader::open(dir.path().to_path_buf()).expect("open reader");

        let alice_results = reader.search("alice", 10).await.expect("search alice");
        assert_eq!(alice_results.len(), 2);

        let budget_results = reader.search("budget", 10).await.expect("search budget");
        assert_eq!(budget_results.len(), 1);
        assert_eq!(budget_results[0].email_id, id1);
        assert!(budget_results[0].score > 0.0);
    }

    #[tokio::test]
    async fn delete_removes_from_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer = IndexWriter::open(dir.path().to_path_buf()).expect("open writer");

        let id1 = EmailId::new();
        writer
            .index_email(
                id1,
                "alice@example.com",
                "bob@example.com",
                "Delete Me",
                "This email should be removed",
            )
            .await
            .expect("index");
        writer.commit().await.expect("commit");

        writer.delete_email(id1).await.expect("delete");
        writer.commit().await.expect("commit");

        let reader = IndexReader::open(dir.path().to_path_buf()).expect("open reader");
        let results = reader.search("delete", 10).await.expect("search");
        assert!(results.is_empty());
    }
}
