import { useState } from 'react'
import EmailTester from './components/EmailTester'
import CalendarTester from './components/CalendarTester'
import './App.css'

type Tab = 'email' | 'calendar'

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>('email')

  return (
    <div className="container">
      <div className="header">
        <h1>Owney Test UI</h1>
        <p>Test email, calendar, and other server features</p>
      </div>

      <div className="tabs">
        <button
          className={`tab-button ${activeTab === 'email' ? 'active' : ''}`}
          onClick={() => setActiveTab('email')}
        >
          Email
        </button>
        <button
          className={`tab-button ${activeTab === 'calendar' ? 'active' : ''}`}
          onClick={() => setActiveTab('calendar')}
        >
          Calendar
        </button>
      </div>

      <div className="tab-content">
        {activeTab === 'email' && <EmailTester />}
        {activeTab === 'calendar' && <CalendarTester />}
      </div>
    </div>
  )
}
