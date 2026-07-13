# Calendar Federation Architecture

Multi-user calendar sharing and delegation with cross-server federation support.

## Overview

The calendar federation system enables:

1. **Same-server sharing**: Share calendars with other users on the same owney instance
2. **Cross-server federation**: Share calendars with users on other owney servers via email discovery
3. **Granular permissions**: Read-only sharing vs. full delegation
4. **Federated email discovery**: Users share calendars using just an email address (e.g., `user@otherdomain.com`)
5. **Acceptance workflow**: Invitations must be accepted before sharing begins
6. **Separate calendar presentation**: API keeps calendars separate; UI toggles merged view

## Core Concepts

### Sharing Types

- **Sharing**: Read-only access to a calendar
  - Can view calendar info and events
  - Cannot modify events
- **Delegation**: Full read-write access (trusted user)
  - Can view and modify events
  - Can change sharing settings
  - Can view sharing/delegation info

### Permission Model

Granular permissions per shared calendar:

```rust
pub struct Permissions {
    pub view_calendar: bool,     // See calendar exists & name
    pub view_events: bool,        // Read event details
    pub edit_events: bool,        // Create, update events
    pub delete_events: bool,      // Delete events
    pub change_sharing: bool,     // Modify calendar sharing
    pub admin: bool,              // Full administrative access
}
```

**Sharing presets**:
- Sharing: view_calendar + view_events only
- Delegation: all permissions true

### Federation Flow

```
User A → Invites user@domain.com
    ↓
Client discovers domain.com's owney server
    ↓
User A's server sends invitation to domain.com's server
    ↓
User B receives invitation, sees it in CalendarInvitation/get
    ↓
User B accepts invitation via CalendarInvitation/set
    ↓
Invitation becomes active CalendarFederation record
    ↓
Both servers establish sync channel (polling initially)
    ↓
User B sees shared calendar in Calendar/get
    ↓
Events sync via polling (can upgrade to webhooks)
```

## Storage Schema

### calendar_sharing
Same-server sharing records.

```sql
CREATE TABLE calendar_sharing (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    shared_with_account_id TEXT NOT NULL,
    sharing_type TEXT,  -- "sharing", "delegation"
    permissions TEXT,   -- JSON
    status TEXT,        -- "pending", "accepted", "rejected", "revoked"
    created_at INTEGER,
    accepted_at INTEGER
);
```

### calendar_invitations
Pending invitations (same-server and federated).

```sql
CREATE TABLE calendar_invitations (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    inviter_account_id TEXT NOT NULL,
    invitee_email TEXT,            -- "user@domain.com" or local
    invitee_server_url TEXT,       -- Set if federated
    sharing_type TEXT,             -- "sharing", "delegation"
    status TEXT,                   -- "pending", "accepted", "rejected"
    message TEXT,
    created_at INTEGER
);
```

### calendar_federation
Cross-server federation state.

```sql
CREATE TABLE calendar_federation (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    target_email TEXT,             -- "user@domain.com"
    target_server_url TEXT,        -- "https://owney.domain.com"
    sharing_type TEXT,
    permissions TEXT,
    status TEXT,                   -- "pending", "accepted", "syncing", "error"
    sync_token TEXT,               -- Opaque token for next sync
    last_sync_at INTEGER,
    created_at INTEGER
);
```

## Well-Known Protocol

### Server Discovery
Clients discover owney servers using fallback chain:

1. `https://domain.com/.well-known/owney/server`
2. `https://mail.domain.com/.well-known/owney/server`
3. `https://owney.domain.com/.well-known/owney/server`
4. DNS SRV record `_owney._tcp.domain.com` (future)

**Response** (application/json):
```json
{
  "server_url": "https://owney.example.com",
  "supported_features": ["calendar_sharing", "calendar_delegation", "federated_discovery"],
  "version": "0.1.0",
  "admin": "admin@example.com"
}
```

### Account Lookup
Public endpoint for federated discovery.

`GET /.well-known/owney/account/{email}`

**Response**:
```json
{
  "account_id": "acc-123",
  "email": "bob@example.com",
  "name": null,
  "calendars": [
    {"id": "cal-1", "name": "Personal"},
    {"id": "cal-2", "name": "Work"}
  ]
}
```

### Receive Invitation
Remote server sends invitation to target server.

`POST /.well-known/owney/calendar/invite`

**Request**:
```json
{
  "calendar_id": "cal-123",
  "calendar_name": "Shared Project",
  "inviter_email": "alice@example.com",
  "inviter_account_id": "acc-alice",
  "inviter_server_url": "https://alice-server.example.com",
  "target_email": "bob@target.com",
  "sharing_type": "sharing",
  "created_at": 1234567890
}
```

**Response** (201 Created):
```json
{
  "invitation_id": "inv-456",
  "status": "pending"
}
```

## JMAP Methods

### Calendar/get
List user's calendars (both own and shared).

```
Request: {
  "accountId": "acc-123",
  "ids": null
}

Response: {
  "accountId": "acc-123",
  "list": [
    {"id": "cal-1", "name": "Personal", "isSubscribed": true},
    {"id": "cal-2", "name": "Shared Project", "isSubscribed": true, ...}
  ]
}
```

### Calendar/share
Share calendar with another user (same-server or federated).

```
Request: {
  "accountId": "acc-123",
  "calendarId": "cal-1",
  "inviteeEmail": "bob@example.com",  // or "alice@other.com" for federation
  "sharingType": "sharing"             // or "delegation"
}

Response: {
  "invitationId": "inv-789",
  "status": "pending",
  "federated": true  // if cross-server
}
```

For same-server: creates CalendarSharing record immediately (pending → accepted workflow).
For federated: discovers remote server, sends invitation, creates CalendarFederation record.

### CalendarInvitation/get
List pending invitations for user.

```
Request: {
  "accountId": "acc-123"
}

Response: {
  "list": [
    {
      "id": "inv-1",
      "calendarId": "cal-shared",
      "inviterAccountId": "acc-alice",
      "sharingType": "sharing",
      "status": "pending",
      "createdAt": 1234567890
    }
  ]
}
```

### CalendarInvitation/set
Accept or reject invitations.

```
Request: {
  "accountId": "acc-123",
  "action": "accept",        // or "reject"
  "invitationId": "inv-1"
}

Response: {
  "invitationId": "inv-1",
  "status": "accepted"       // or "rejected"
}
```

## Synchronization

### Polling (Current)
Background job polls remote servers at intervals:

```rust
pub async fn sync_federation(&self, job: FederationSyncJob) -> Result<()> {
    let sync_response = self.fetch_remote_changes(&job).await?;
    // Upsert events from remote
    // Delete removed events
    // Update sync_token for next sync
}
```

Remote server endpoint (to be implemented):
`GET /calendar-sync?federation_id=...&token=...`

Response includes delta of changes since last sync token.

### Webhook (Future)
Remote servers can push changes via webhook to avoid polling:

`POST /.well-known/owney/calendar/sync-webhook`

Allows real-time sync without polling overhead.

## Implementation Status

### ✅ Implemented
- Storage models and migrations
- Server discovery protocol
- Well-known endpoints
- JMAP methods
- Permission model

### 🚧 In Progress
- Sync framework (polling skeleton)
- Event sync protocol
- Tests

### 📋 Future
- Webhook-based sync
- Calendar subscription management
- Conflict resolution
- Event-level permissions
- Recurring event federation
- Mobile/web client support

## Security Considerations

1. **Server trust**: HTTPS only, optional allowlist of trusted servers
2. **Account verification**: Email-based discovery only verifies account exists
3. **Permission isolation**: Shared calendars are separate objects, no access to other calendars
4. **Audit trail**: All sharing changes logged via StateChange events
5. **Token expiry**: Sync tokens expire after 30 days (prevents old tokens)
6. **Rate limiting**: Poll intervals and request rates to prevent abuse

## Testing Strategy

1. **Storage tests**: Calendar sharing/invitation workflows
2. **Discovery tests**: Server lookup, account discovery
3. **JMAP tests**: Method argument validation, response format
4. **Sync tests**: Polling, event sync, conflict resolution
5. **Federation tests**: End-to-end cross-server scenarios

## Future Enhancements

1. **Event-level sharing**: Share specific event subsets
2. **Group sharing**: Share with multiple users at once
3. **Availability view**: Show only free/busy (not event details)
4. **Task lists**: Share task/todo lists alongside calendars
5. **Recurring event expansions**: Special handling for recurring events across servers
6. **Calendar subscriptions**: Subscribe to public calendars without sharing
7. **Performance**: Caching of shared calendars, background sync scheduling
