# Owney Test UI - Quick Start

## What Was Created

A React-based test UI with Vite bundling that:
- Tests email operations (search, list, get mailboxes)
- Tests calendar operations (calendars, events, shares, invitations)
- Stores JMAP bearer token in localStorage
- Displays raw API responses for inspection

## Quick Start (Copy/Paste)

```bash
# 1. Install UI dependencies (one time)
cd ui
npm install

# 2. Build UI into Rust static folder
npm run build

# 3. In a separate terminal, run the Rust server
cargo build --release
./target/release/owneyd

# 4. Open http://localhost:8008 in your browser
```

## Development Mode (Recommended)

Run these **in separate terminals**:

**Terminal 1 - Watch UI changes:**
```bash
cd ui
npm run dev
# Opens http://localhost:5173
```

**Terminal 2 - Run Rust backend:**
```bash
cargo run --release
# Runs on http://localhost:8008
```

Visit `http://localhost:5173` - Vite dev server has hot reload built in.

## How to Use the UI

1. **Get a JMAP Token**: Create an account on your server and get its bearer token
2. **Paste Token**: In the UI, paste your token in the "JMAP Bearer Token" field
3. **Test Features**: Click buttons to test email and calendar operations
4. **View Responses**: Raw JSON responses show below each operation

## File Structure

```
ui/
├── src/
│   ├── components/
│   │   ├── EmailTester.tsx     - Email operations
│   │   └── CalendarTester.tsx  - Calendar operations  
│   ├── App.tsx                 - Main app + tabs
│   ├── api.ts                  - JMAP client helper
│   └── index.css               - Global styles
├── vite.config.ts              - Build config
└── package.json                - Dependencies

crates/owney-api/
└── static/                      - Built UI (created by npm run build)
```

## Adding Tests for New Features

Create a new component file, e.g., `ContactsTester.tsx`:

```tsx
import { useState } from 'react'
import { callJmap, getSession } from '../api'

export default function ContactsTester() {
  const [status, setStatus] = useState('')
  const [response, setResponse] = useState('')
  const token = localStorage.getItem('jmap_token')

  const handleGetContacts = async () => {
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['Contact/get', { accountId }, '0'],
      ])
      setStatus('✓ Contacts retrieved')
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error.message}`)
    }
  }

  return (
    <div>
      <button onClick={handleGetContacts} disabled={!token}>Get Contacts</button>
      {status && <div className={`status ${status.startsWith('✓') ? 'success' : 'error'}`}>{status}</div>}
      {response && <div className="response-box">{response}</div>}
    </div>
  )
}
```

Then add to `App.tsx`:
- Import the component
- Add a tab button
- Show it based on activeTab

## Environment

- **UI**: React 18, Vite (fast builds), TypeScript
- **Styling**: Plain CSS (no framework yet)
- **Storage**: JMAP token saved to localStorage
- **API**: Calls `/jmap/api` endpoint with Bearer token

## Troubleshooting

**"Cannot find module" error during build?**
```bash
cd ui && npm install && npm run build
```

**Server not serving UI?**
Make sure `npm run build` completed successfully. Check that `crates/owney-api/static/` exists.

**CORS/Auth errors in browser?**
1. Copy your JMAP bearer token from server
2. Paste into the "JMAP Bearer Token" field
3. Refresh browser
4. Try again

**Port 8008 in use?**
```bash
LISTEN_ADDR=127.0.0.1:9999 cargo run --release
# Then visit http://localhost:9999
```

## Next: Building a Real UI

This is the foundation. Once you're ready to build the full UI:

1. Keep this test UI as a reference
2. Start a new, larger React app (CRA, Next.js, or Vite with more structure)
3. Use the same `api.ts` patterns for JMAP calls
4. Gradually add real features (compose, calendar UI, etc.)

## Key APIs Available

- **Email**: `Email/get`, `Email/query`, `Mailbox/get`, `Mailbox/query`
- **Calendar**: `Calendar/get`, `CalendarEvent/get`, `CalendarEvent/query`, `CalendarEventShare/get`, `CalendarEventInvitation/get`
- **Core**: Session info, upload, download, WebSocket events

See JMAP RFC 8621 for full method documentation.
