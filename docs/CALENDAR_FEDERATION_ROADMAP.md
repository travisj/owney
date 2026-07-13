# Calendar Federation Roadmap

## Phase Summary

### Phase 1: Foundation (✅ Completed - 2026-07-13)

**Goal**: Build storage, discovery, and JMAP foundation for federation.

**Deliverables**:
- ✅ Storage models: CalendarSharing, CalendarInvitation, CalendarFederation
- ✅ Database migrations (15→16→17) with proper indexes
- ✅ Permission model with granular controls
- ✅ ServerDiscovery protocol with fallback chain
- ✅ Well-known endpoints (server, account, invite)
- ✅ JMAP methods (Calendar/get, Calendar/share, CalendarInvitation/*)
- ✅ Sync framework skeleton
- ✅ Comprehensive documentation
- ✅ Storage layer tests

**Commits**:
- 6eddf2a: feat(calendar): storage layer for sharing, delegation, and federation
- 94ed570: feat(calendar): add sync framework, tests, and federation docs

### Phase 2: Event Sync (⏳ Next)

**Goal**: Implement polling-based event synchronization and local storage.

**Tasks**:
1. Background sync worker
   - Periodic task to sync all active federations
   - Configurable poll intervals (suggest 5-15 min for initial implementation)
   - Exponential backoff on errors

2. Event sync protocol
   - Implement remote server sync endpoint: `GET /calendar-sync?token=...`
   - Return delta of changed events since sync token
   - Include removed event IDs for cleanup
   - Generate next sync token

3. Event application
   - Upsert events from remote
   - Handle event deletions
   - Track remote event IDs for proper attribution
   - Collision detection (local event modified during remote sync)

4. Sync error handling
   - Retry logic with backoff
   - Error state in calendar_federation table
   - Admin notifications for persistent failures

5. Tests
   - Single federation sync test
   - Multi-event sync test
   - Deleted event handling
   - Sync token advancement
   - Error recovery

**Estimated effort**: 3-4 hours

### Phase 3: UI Integration (⏳ Next)

**Goal**: Update web/mobile UI to expose calendar sharing.

**Tasks**:
1. Calendar list page
   - Show owned and shared calendars separately
   - Indicate sharing type (shared by me / shared with me)
   - Sharing icon/badge for delegated calendars

2. Sharing dialog
   - "Share calendar" button
   - Email input with autocomplete (local + federated lookups)
   - Sharing type selector (sharing / delegation)
   - Send button

3. Invitation inbox
   - List pending invitations
   - Accept/Reject/View details buttons
   - Show inviter, calendar name, sharing type

4. Calendar settings
   - Sharing management page
   - List of who calendar is shared with
   - Revoke sharing button per person
   - Modify sharing type (if admin)

5. Merged calendar toggle
   - Calendar list with checkboxes
   - Toggle individual calendars on/off in merged view
   - Persist preferences per session

**Estimated effort**: 6-8 hours

### Phase 4: Webhook Push Sync (⏳ Future)

**Goal**: Implement webhook-based real-time sync to replace polling.

**Tasks**:
1. Webhook endpoint
   - `POST /.well-known/owney/calendar/sync-webhook`
   - Receive push notifications from remote servers
   - Queue immediate sync jobs

2. Webhook registration
   - Register this server's webhook URL when creating federation
   - Send registration request to remote server
   - Support webhook revocation on deletion

3. Webhook security
   - HMAC-SHA256 signature verification
   - Timestamp validation (prevent replay attacks)
   - Webhook URL allowlist for receiving

4. Webhook client
   - Queue webhook delivery attempts
   - Retry logic with exponential backoff
   - Handle webhook delivery failures

**Estimated effort**: 4-5 hours

### Phase 5: Advanced Features (⏳ Future)

**Goal**: Additional functionality and optimizations.

**Tasks**:

#### 5a. Event-level sharing
- Share specific calendar subsets
- Filter events by category/label
- Privacy control (show only free/busy)

#### 5b. Group sharing
- Share calendar with multiple users at once
- Bulk invitation workflow
- Group management

#### 5c. Recurring events
- Proper expansion of recurring events for shared calendars
- Handle attendee-specific recurrence changes
- Sync recurring exceptions

#### 5d. Performance optimizations
- Cache shared calendars (invalidate on changes)
- Batch sync of multiple federations
- Connection pooling for remote servers
- Partial sync (only events in date range)

#### 5e. Calendar subscriptions
- Subscribe to public calendars
- Granular permission for subscription-only

#### 5f. Admin features
- Server allowlist for federation
- Rate limiting per remote server
- Audit log of all sharing changes
- Disable federation globally

**Estimated effort**: 15-20 hours total

## Dependencies & Constraints

### Technology Stack
- **Sync runtime**: Use tokio for background tasks
- **HTTP client**: reqwest (already in dependencies)
- **Serialization**: serde_json
- **Database**: SQLite (via rusqlite)

### Configuration Needed
- `calendar.sync_interval_secs`: Poll interval (default 300s/5min)
- `calendar.webhook_timeout_secs`: Webhook delivery timeout (default 30s)
- `calendar.max_sync_backoff_secs`: Max retry backoff (default 3600s/1hr)
- `calendar.server_url`: This server's public URL (for federation)
- `calendar.federation_allowlist`: Optional allowlist of trusted servers
- `calendar.federation_enabled`: Toggle federation on/off

### Backwards Compatibility
- Calendar storage is new (M11), no migration concerns
- Existing calendar tables unchanged
- New methods don't break existing JMAP clients

## Estimated Timeline

- **Phase 1**: Complete (16 hours of work)
- **Phase 2**: ~3-4 hours → 1-2 days
- **Phase 3**: ~6-8 hours → 2-3 days  
- **Phase 4**: ~4-5 hours → 1-2 days (optional, not blocking)
- **Phase 5**: ~15-20 hours (nice-to-haves, can be spread over time)

**Total for full feature**: ~35-40 hours (~1-2 weeks of focused dev)

## Success Criteria

### Phase 2 (Event Sync)
- [ ] Background sync worker runs periodically
- [ ] Events sync between two local instances
- [ ] Sync tokens advance properly
- [ ] Deleted events removed from shared calendar
- [ ] Sync errors don't crash server

### Phase 3 (UI)
- [ ] Users can share calendars via web
- [ ] Invitations appear in UI
- [ ] Users can accept/reject invitations
- [ ] Shared calendars appear in calendar list
- [ ] Calendar toggle affects merged view

### Phase 4 (Webhooks)
- [ ] Real-time sync via push notifications
- [ ] Fallback to polling on webhook failures
- [ ] Webhook signatures verified
- [ ] No duplicate events from webhook + polling

### Phase 5 (Advanced)
- [ ] All advanced features tested
- [ ] Performance acceptable (< 100ms for calendar list)
- [ ] Error handling robust

## Risk Mitigation

### Data Consistency
- **Risk**: Events out of sync during network failures
- **Mitigation**: Sync tokens, idempotent event upserts, retry logic

### Performance
- **Risk**: Polling too aggressive causes server load
- **Mitigation**: Configurable intervals, batch sync, webhook alternative

### Security
- **Risk**: Unauthorized servers impersonate trusted servers
- **Mitigation**: HTTPS only, server allowlist, HMAC signatures

### User Experience
- **Risk**: Confusing UI with many shared calendars
- **Mitigation**: Clear labeling, separate shared/owned, toggle feature

## Next Steps

1. Implement Phase 2 (event sync)
2. Add configuration for sync intervals
3. Integration test with two local instances
4. Performance test with large calendar (1000+ events)
5. Code review of sync protocol
6. Deploy to staging
7. QA testing
