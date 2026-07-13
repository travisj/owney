import { useState } from 'react'
import { callJmap, getSession } from '../api'

export default function CalendarTester() {
  const [status, setStatus] = useState('')
  const [response, setResponse] = useState('')
  const [loading, setLoading] = useState(false)
  const token = localStorage.getItem('jmap_token')

  const handleGetCalendars = async () => {
    setLoading(true)
    setStatus('')
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['Calendar/get', { accountId }, '0'],
      ])
      setStatus('✓ Calendars retrieved')
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error instanceof Error ? error.message : 'Unknown error'}`)
      setResponse('')
    } finally {
      setLoading(false)
    }
  }

  const handleGetEvents = async () => {
    setLoading(true)
    setStatus('')
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['CalendarEvent/query', { accountId, limit: 20 }, '0'],
      ])
      setStatus('✓ Calendar events retrieved')
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error instanceof Error ? error.message : 'Unknown error'}`)
      setResponse('')
    } finally {
      setLoading(false)
    }
  }

  const handleListShares = async () => {
    setLoading(true)
    setStatus('')
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['CalendarEventShare/get', { accountId }, '0'],
      ])
      setStatus('✓ Shared calendars retrieved')
      setResponse(JSON.stringify(result, null, 2))
    } catch (error) {
      setStatus(`✗ ${error instanceof Error ? error.message : 'Unknown error'}`)
      setResponse('')
    } finally {
      setLoading(false)
    }
  }

  const handleListInvitations = async () => {
    setLoading(true)
    setStatus('')
    try {
      const session = await getSession()
      const accountId = Object.keys(session.accounts)[0]
      const result = await callJmap([
        ['CalendarEventInvitation/get', { accountId }, '0'],
      ])
      setStatus('✓ Invitations retrieved')
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
        <strong>Calendar Features:</strong> Test calendar operations including getting calendars, events, shares, and invitations.
      </div>

      <div className="section">
        <h2>Calendar Operations</h2>
        <div className="button-group">
          <button onClick={handleGetCalendars} disabled={!token || loading}>
            {loading ? 'Loading...' : 'Get Calendars'}
          </button>
          <button onClick={handleGetEvents} disabled={!token || loading}>
            {loading ? 'Loading...' : 'Get Events'}
          </button>
          <button onClick={handleListShares} disabled={!token || loading}>
            {loading ? 'Loading...' : 'Get Shares'}
          </button>
          <button onClick={handleListInvitations} disabled={!token || loading}>
            {loading ? 'Loading...' : 'Get Invitations'}
          </button>
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
