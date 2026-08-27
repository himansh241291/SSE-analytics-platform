'use client'

import { useEffect, useState } from 'react'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

const tabs = ['Overview', 'Threats', 'Traffic', 'DNS', 'Web / Proxy', 'Firewall', 'DLP', 'ZTNA', 'Users', 'Investigations']

export default function Home() {
  const [overview, setOverview] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [sources, setSources] = useState([])
  const [users, setUsers] = useState([])
  const [recent, setRecent] = useState([])
  const [error, setError] = useState('')

  useEffect(() => {
    const load = async () => {
      try {
        const [o, t, s, u, r] = await Promise.all([
          fetch(`${API}/api/overview`).then(x => x.json()),
          fetch(`${API}/api/timeline`).then(x => x.json()),
          fetch(`${API}/api/by-source`).then(x => x.json()),
          fetch(`${API}/api/top-users`).then(x => x.json()),
          fetch(`${API}/api/recent?limit=20`).then(x => x.json()),
        ])
        setOverview(o)
        setTimeline(t)
        setSources(s)
        setUsers(u)
        setRecent(r)
      } catch (e) {
        setError('Dashboard API is unavailable. Start the API and refresh.')
      }
    }
    load()
  }, [])

  const cards = [
    ['Events', overview?.events ?? '—'],
    ['Blocked', overview?.blocked ?? '—'],
    ['High Severity', overview?.high_severity ?? '—'],
    ['DLP Events', overview?.dlp ?? '—'],
    ['Users', overview?.users ?? '—'],
  ]

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">SECURITY ANALYTICS</div>
          <h1>SSE Security Analytics</h1>
          <p>Unified telemetry and investigation view</p>
        </div>
        <div className="status">LIVE DATA · {overview ? 'CONNECTED' : 'CONNECTING'}</div>
      </header>

      <nav className="tabs">{tabs.map(tab => <button key={tab} className={tab === 'Overview' ? 'active' : ''}>{tab}</button>)}</nav>

      {error && <div className="error">{error}</div>}

      <section className="cards">
        {cards.map(([label, value]) => <div className="card" key={label}><span>{label}</span><strong>{typeof value === 'number' ? value.toLocaleString() : value}</strong></div>)}
      </section>

      <section className="grid2">
        <Panel title="Event Timeline">
          <div className="bars">
            {timeline.map((p, i) => <div className="barWrap" key={i} title={`${p.timestamp}: ${p.events} events`}><div className="bar" style={{height: `${Math.max(8, Math.min(100, p.events / Math.max(1, ...timeline.map(x => x.events)) * 100))}%`}}></div></div>)}
          </div>
        </Panel>
        <Panel title="Events by Source">
          <div className="sourceList">{sources.map(x => <div className="sourceRow" key={x.source}><span>{x.source}</span><b>{Number(x.events).toLocaleString()}</b></div>)}</div>
        </Panel>
      </section>

      <section className="grid2">
        <Panel title="Top Users">
          <div className="sourceList">{users.map(x => <div className="sourceRow" key={x.user}><span>{x.user}</span><b>{Number(x.events).toLocaleString()}</b></div>)}</div>
        </Panel>
        <Panel title="Recent Security Events">
          <div className="tableWrap"><table><thead><tr><th>Time</th><th>Source</th><th>User</th><th>Destination</th><th>Action</th></tr></thead><tbody>{recent.map((x, i) => <tr key={i}><td>{String(x.event_time).replace('T', ' ').slice(0, 19)}</td><td>{x.source_type}</td><td>{x.user_identity || '—'}</td><td>{x.destination || x.destination_ip || '—'}</td><td>{x.action || '—'}</td></tr>)}</tbody></table></div>
        </Panel>
      </section>
    </main>
  )
}

function Panel({ title, children }) {
  return <div className="panel"><div className="panelTitle">{title}</div>{children}</div>
}
