# Calendar Sync Protocol Specification

Version: 1.0 (Draft)

For federated cross-server calendar synchronization.

## Overview

Owney uses a polling-based sync protocol for federated calendars. Each server maintaining a shared calendar periodically polls the source server for changes.

**Transport**: HTTP/HTTPS with JSON

**Authentication**: (Future) Bearer token or mutual TLS

## Endpoints

### 1. Sync State Endpoint

Fetch changes to a shared calendar since last sync.

```
GET /.well-known/owney/calendar/sync/{federation_id}
```

**Query Parameters**:
- `token` (optional): Sync token from previous response. Omit for initial sync.
- `since_timestamp` (optional): Unix timestamp of last sync (backup if token lost).

**Response** (200 OK):
```json
{
  "federation_id": "fed-123",
  "sync_token": "2026-07-13T12:30:45Z:abc123",
  "calendar": {
    "id": "cal-456",
    "name": "Project Planning",
    "description": "Team project calendar",
    "updated_at": 1689246645
  },
  "events": [
    {
      "id": "evt-1",
      "title": "Team Standup",
      "description": "Daily sync",
      "start": 1689334200,
      "end": 1689335100,
      "rrule": "FREQ=DAILY;UNTIL=20260831T235959Z",
      "created_at": 1689246000,
      "updated_at": 1689246100,
      "removed": false
    },
    {
      "id": "evt-2",
      "removed": true
    }
  ],
  "removed_event_ids": ["evt-999"],
  "has_more_changes": false,
  "next_token": "2026-07-13T12:31:00Z:def456"
}
```

**Response Fields**:
- `federation_id`: Echo of the federation being synced
- `sync_token`: Opaque token for next sync. Include in next request.
- `calendar`: Calendar metadata (name, description). May be omitted if unchanged.
- `events`: Array of changed events (created, updated, or marked removed)
  - `removed: true` means event was deleted
  - Include all fields for new/updated events
  - For removed events, only `id` and `removed` fields needed
- `removed_event_ids`: List of event IDs deleted (alternative format)
- `has_more_changes`: If `true`, client should request again immediately
- `next_token`: Token to use for next request

**Error Responses**:

```json
{
  "error": "invalid_token",
  "error_description": "Sync token expired or invalid"
}
```

Error codes:
- `invalid_token`: Token expired (> 30 days old). Start fresh sync.
- `not_found`: Federation ID doesn't exist or access revoked.
- `unauthorized`: Client not authorized to sync this calendar.
- `rate_limited`: Too many requests. Retry after `Retry-After` header.
- `server_error`: Server error. Retry with backoff.

### 2. Account Info Endpoint

(Already specified in CALENDAR_FEDERATION.md)

`GET /.well-known/owney/account/{email}`

## Sync Protocol State Machine

```
[Initial Sync]
    │
    ├─> GET /.well-known/owney/calendar/sync/{fed_id} (no token)
    │
    └─> [Receive events + sync_token]
            │
            ├─> Upsert events locally
            ├─> Delete removed events
            ├─> Store sync_token
            │
            └─> [Idle]
                  │
                  └─> [Poll interval expires]
                      │
                      └─> GET /.well-known/owney/calendar/sync/{fed_id}?token=...
                          │
                          └─> [Back to receive]
```

## Event Fields

### Required
- `id`: Unique event ID on remote server
- `title`: Event title
- `start`: Unix timestamp (seconds)
- `end`: Unix timestamp (seconds)

### Optional
- `description`: Event description
- `rrule`: RFC 5545 recurrence rule (e.g., "FREQ=DAILY;UNTIL=...")
- `created_at`: Unix timestamp when event created
- `updated_at`: Unix timestamp when event last modified

### Notes
- All timestamps must be Unix timestamps (seconds since epoch)
- No timezone info in protocol (events are assumed in calendar's timezone)
- IDs must be globally unique within the source calendar
- Clients must treat IDs as opaque strings

## Sync Token Format

Opaque strings. Servers MAY use any format:
- Timestamp-based: `2026-07-13T12:30:45Z:abc123`
- Hash-based: `sha256-f7a9b8c...`
- Sequence-based: `seq-12345`

Clients must:
- Store token exactly as received
- Pass token unchanged in next request
- Handle token expiry gracefully (restart full sync)

## Error Handling

### Client-side

**Permanent errors** (abort this federation's sync):
- `not_found`: Access revoked, don't retry
- `unauthorized`: Authentication failed

**Temporary errors** (retry with backoff):
- Network timeout
- 5xx errors
- `rate_limited`

**Recovery**:
- 1st failure: retry after 30 seconds
- 2nd failure: retry after 2 minutes
- 3rd failure: retry after 15 minutes
- 4th+ failure: retry after 1 hour, mark federation as error

**On token expiry** (`invalid_token`):
- Clear sync token
- Resume full sync (no token)

### Server-side

**Rate Limiting**:
- Recommend 10-60 requests per minute per federation
- Return `429 Too Many Requests` with `Retry-After` header
- Include reason in response

**Load Shedding**:
- If server overloaded, return `503 Service Unavailable`
- Clients back off appropriately

## Security

### Transport
- HTTPS only, no HTTP
- TLS 1.2 minimum
- Valid certificate required

### Authentication (Future)
- Bearer token in `Authorization` header
- OR mutual TLS (client certificate)
- Implement in Phase 4 with webhook integration

### Rate Limiting
- Per-federation rate limit
- Per-remote-server aggregate limit
- Prevent polling DoS

### Integrity
- Webhook responses include HMAC-SHA256 signature
- Verify signature on receipt

## Polling Strategy

**Recommended approach**:

```
Base interval: 5 minutes (300 seconds)
Max interval: 1 hour (3600 seconds)
Jitter: ±10% to prevent thundering herd

For each federation:
  - First sync: immediate
  - Subsequent: base_interval + random(-jitter, +jitter)
  - If `has_more_changes: true`: retry immediately
  - On backoff: increase interval up to max
  - On success: reset to base interval
```

**Example schedule**:

```
Federation A: poll at 12:05 (immediate)
Federation B: poll at 12:07 (base + jitter)
Federation A: poll at 12:10 (base + jitter)
Federation B: poll at 12:12 (base + jitter)
...
```

## Future Enhancements

### Webhook Push
(Phase 4)

```
POST /webhook-endpoint
Authorization: Bearer {token}
X-Signature: sha256={hmac}

{
  "type": "calendar.sync_available",
  "federation_id": "fed-123",
  "updated_at": 1689246645
}
```

### Partial Sync
(Phase 5)

Request events in date range:

```
GET /.well-known/owney/calendar/sync/{federation_id}?token=...&since=1689000000&until=1690000000
```

Only return events in the requested window.

### Compression
(Phase 5)

Support gzip encoding:

```
GET /.well-known/owney/calendar/sync/{federation_id}?token=...
Accept-Encoding: gzip
```

### OAuth2 Auth
(Phase 4)

Use OAuth2 for server-to-server authentication instead of bearer tokens.

## Compatibility

### Versions
- Version 1.0: Current spec

### Client Requirements
- HTTP/1.1 minimum
- JSON parsing
- Unix timestamp support
- Backoff/retry logic

### Server Requirements
- HTTP/1.1 support
- JSON serialization
- Sync token tracking
- Rate limiting

## Testing

### Mock Server
See `crates/owney-api/tests/fixtures/mock_sync_server.rs`

### Test Cases
1. Initial sync (no token)
2. Incremental sync (with token)
3. Token expiry (invalid_token)
4. New/modified/deleted events
5. Pagination (has_more_changes)
6. Rate limiting
7. Network errors
8. Malformed responses
9. Missing required fields
10. Large event count (1000+)

## Examples

### Initial Sync Request

```
GET https://alice-server.example.com/.well-known/owney/calendar/sync/fed-123

Response 200 OK:
{
  "federation_id": "fed-123",
  "sync_token": "t123-abc",
  "calendar": {
    "id": "cal-456",
    "name": "Shared"
  },
  "events": [
    {
      "id": "evt-1",
      "title": "Meeting",
      "start": 1689334200,
      "end": 1689335100,
      "updated_at": 1689246100
    }
  ]
}
```

### Incremental Sync Request

```
GET https://alice-server.example.com/.well-known/owney/calendar/sync/fed-123?token=t123-abc

Response 200 OK:
{
  "federation_id": "fed-123",
  "sync_token": "t123-def",
  "events": [
    {
      "id": "evt-2",
      "title": "New Event",
      "start": 1689420600,
      "end": 1689421500
    },
    {
      "id": "evt-1",
      "removed": true
    }
  ]
}
```

### Expired Token

```
GET https://alice-server.example.com/.well-known/owney/calendar/sync/fed-123?token=old-token

Response 400 Bad Request:
{
  "error": "invalid_token",
  "error_description": "Token is older than 30 days. Please start a new sync."
}

Client action: Retry without token (fresh sync)
```
