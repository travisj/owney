export interface JmapRequest {
  using: string[]
  methodCalls: Array<[string, Record<string, unknown>, string]>
}

export async function callJmap(methodCalls: Array<[string, Record<string, unknown>, string]>) {
  const token = localStorage.getItem('jmap_token')
  if (!token) {
    throw new Error('No auth token. Please set JMAP_TOKEN in localStorage.')
  }

  const body: JmapRequest = {
    using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail', 'urn:ietf:params:jmap:calendars'],
    methodCalls,
  }

  const response = await fetch('/jmap/api', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    throw new Error(`JMAP error: ${response.status} ${response.statusText}`)
  }

  const data = await response.json()
  return data
}

export async function getSession() {
  const token = localStorage.getItem('jmap_token')
  if (!token) {
    throw new Error('No auth token.')
  }

  const response = await fetch('/.well-known/jmap', {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  })

  if (!response.ok) {
    throw new Error(`Session error: ${response.status}`)
  }

  return await response.json()
}
