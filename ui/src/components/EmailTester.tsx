import { useState } from 'react'
import { callJmap, getSession } from '../api'

export default function EmailTester() {
  const [token, setToken] = useState(localStorage.getItem('jmap_token') || '')
  const [status, setStatus] = useState('')
  const [response, setResponse] = useState('')
  const [loading, setLoading] = useState(false)

  const updateToken = (newToken: string) => {
    setToken(newToken)
    localStorage.setItem('jmap_token', newToken)
  }

  const handleGetSession = async () => {
    setLoading(true)
    setStatus('')
    try {
      const result = await getSession()
      setStatus('✓ Session retrieved')
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error instanceof Error ? error.message : 'Unknown error'}`)
      setResponse('')
    } finally {
      setLoading(false)
    }
  }

  const handleGetMailboxes = async () => {
    setLoading(true)
    setStatus('')
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['Mailbox/get', { accountId }, '0'],
      ])
      setStatus('✓ Mailboxes retrieved')
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error instanceof Error ? error.message : 'Unknown error'}`)
      setResponse('')
    } finally {
      setLoading(false)
    }
  }

  const handleGetEmails = async () => {
    setLoading(true)
    setStatus('')
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['Email/query', { accountId, limit: 10 }, '0'],
      ])
      setStatus('✓ Email query sent')
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error instanceof Error ? error.message : 'Unknown error'}`)
      setResponse('')
    } finally {
      setLoading(false)
    }
  }

  const handleSearchEmails = async (query: string) => {
    if (!query.trim()) {
      setStatus('✗ Enter a search query')
      return
    }
    setLoading(true)
    setStatus('')
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['Email/query', { accountId, filter: { text: query }, limit: 20 }, '0'],
      ])
      setStatus(`✓ Search for "${query}" completed`)
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error instanceof Error ? error.message : 'Unknown error'}`)
      setResponse('')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="info">
        <strong>Authentication:</strong> Enter your JMAP bearer token below to get started. Get this from your server.
      </div>

      <div className="section">
        <div className="form-group">
          <label>JMAP Bearer Token</label>
          <input
            type="password"
            value={token}
            onChange={(e) => updateToken(e.target.value)}
            placeholder="Enter your JMAP bearer token..."
          />
          <small style={{ display: 'block', marginTop: 5, color: '#666' }}>
            Saved to localStorage
          </small>
        </div>
      </div>

      <div className="section">
        <h2>Core Operations</h2>
        <div className="button-group">
          <button onClick={handleGetSession} disabled={!token || loading}>
            {loading ? 'Loading...' : 'Get Session'}
          </button>
          <button onClick={handleGetMailboxes} disabled={!token || loading}>
            {loading ? 'Loading...' : 'Get Mailboxes'}
          </button>
          <button onClick={handleGetEmails} disabled={!token || loading}>
            {loading ? 'Loading...' : 'Get Recent Emails'}
          </button>
        </div>
      </div>

      <div className="section">
        <h2>Search Emails</h2>
        <div className="form-group">
          <label>Search Query</label>
          <div style={{ display: 'flex', gap: 10 }}>
            <input
              id="searchInput"
              type="text"
              placeholder="e.g., 'from:alice@example.com' or 'subject:hello'"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && token && !loading) {
                  handleSearchEmails(e.currentTarget.value)
                }
              }}
              style={{ flex: 1 }}
            />
            <button
              onClick={() => {
                const input = document.getElementById('searchInput') as HTMLInputElement
                handleSearchEmails(input?.value || '')
              }}
              disabled={!token || loading}
            >
              Search
            </button>
          </div>
        </div>
      </div>

      {status && (
        <div className={`status ${status.startsWith('✓') ? 'success' : status.startsWith('✗') ? 'error' : 'loading'}`}>
          {status}
        </div>
      )}

      {response && (
        <div className="response-box">
          {response}
        </div>
      )}
    </div>
  )
}
