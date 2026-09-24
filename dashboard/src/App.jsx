import { useState, useEffect } from 'react'
import './App.css'

const API_BASE = 'http://localhost:8000'

// Which severity tier a rule maps to, purely for badge color - not a
// detection concept, just a presentation one.
const SEVERITY = {
  file_integrity_violation: 'critical',
  ssh_brute_force: 'high',
  web_attack_probing: 'high',
  ssh_recon_scan: 'medium',
  port_scan_detected: 'medium',
}

function severityOf(ruleName) {
  return SEVERITY[ruleName] || 'medium'
}

function RuleBadge({ ruleName }) {
  return <span className={`badge badge-${severityOf(ruleName)}`}>{ruleName}</span>
}

function MitreBadge({ technique }) {
  if (!technique) return null
  return <span className="mitre-badge">{technique}</span>
}

function AlertsList({ onSelectAlert, onSelectIncident }) {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchAlerts = () => {
      fetch(`${API_BASE}/alerts`)
        .then((res) => {
          if (!res.ok) throw new Error(`API returned ${res.status}`)
          return res.json()
        })
        .then((data) => {
          setAlerts(data)
          setLoading(false)
        })
        .catch((err) => {
          setError(err.message)
          setLoading(false)
        })
    }

    fetchAlerts()
    const intervalId = setInterval(fetchAlerts, 5000)

    return () => clearInterval(intervalId)
  }, [])

  if (loading) return <p className="dashboard">Loading alerts...</p>
  if (error) return <p className="dashboard">Error loading alerts: {error}</p>

  return (
    <div className="dashboard">
      <h2 className="section-title">
        Alerts
        <span className="count-pill">{alerts.length}</span>
      </h2>
      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Rule</th>
              <th>MITRE</th>
              <th>Source IP</th>
              <th>Username</th>
              <th>Description</th>
              <th>Incident</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id} onClick={() => onSelectAlert(alert.id)} className="clickable-row">
                <td>{new Date(alert.created_at).toLocaleString()}</td>
                <td><RuleBadge ruleName={alert.rule_name} /></td>
                <td><MitreBadge technique={alert.mitre_technique} /></td>
                <td>{alert.source_ip || '—'}</td>
                <td>{alert.username || '—'}</td>
                <td>{alert.description}</td>
                <td>
                  {alert.incident_id ? (
                    <button
                      className="btn btn-tag"
                      onClick={(e) => {
                        e.stopPropagation()
                        onSelectIncident(alert.incident_id)
                      }}
                    >
                      #{alert.incident_id}
                    </button>
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function AlertDetail({ alertId, onBack, onSelectIncident }) {
  const [alert, setAlert] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch(`${API_BASE}/alerts/${alertId}`)
      .then((res) => {
        if (!res.ok) throw new Error(`API returned ${res.status}`)
        return res.json()
      })
      .then((data) => {
        setAlert(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [alertId])

  if (loading) return <p className="dashboard">Loading alert detail...</p>
  if (error) return <p className="dashboard">Error loading alert: {error}</p>

  return (
    <div className="dashboard">
      <button className="btn btn-back" onClick={onBack}>&larr; Back to alerts</button>
      <h2 style={{ marginBottom: '1.25rem' }}>Alert #{alert.id}</h2>

      <div className="meta-grid">
        <div className="meta-item">
          <span className="meta-label">Rule</span>
          <RuleBadge ruleName={alert.rule_name} />
        </div>
        <div className="meta-item">
          <span className="meta-label">MITRE Technique</span>
          <MitreBadge technique={alert.mitre_technique} />
        </div>
        <div className="meta-item">
          <span className="meta-label">Source IP</span>
          <span className="meta-value mono">{alert.source_ip || '—'}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">Username</span>
          <span className="meta-value mono">{alert.username || '—'}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">Event Count</span>
          <span className="meta-value mono">{alert.event_count}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">Incident</span>
          {alert.incident_id ? (
            <button className="btn btn-tag" onClick={() => onSelectIncident(alert.incident_id)}>
              View #{alert.incident_id}
            </button>
          ) : (
            <span className="meta-value">Not correlated</span>
          )}
        </div>
      </div>

      <p className="description">{alert.description}</p>

      <h3 style={{ marginBottom: '0.75rem' }}>Timeline</h3>
      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Event Type</th>
              <th>Raw Log</th>
            </tr>
          </thead>
          <tbody>
            {alert.events.map((event) => (
              <tr key={event.id}>
                <td>{new Date(event.event_time).toLocaleString()}</td>
                <td>{event.event_type}</td>
                <td><span className="raw-log">{event.raw_log}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function IncidentsList({ onSelectIncident }) {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchIncidents = () => {
      fetch(`${API_BASE}/incidents`)
        .then((res) => {
          if (!res.ok) throw new Error(`API returned ${res.status}`)
          return res.json()
        })
        .then((data) => {
          setIncidents(data)
          setLoading(false)
        })
        .catch((err) => {
          setError(err.message)
          setLoading(false)
        })
    }

    fetchIncidents()
    const intervalId = setInterval(fetchIncidents, 5000)

    return () => clearInterval(intervalId)
  }, [])

  if (loading) return <p className="dashboard">Loading incidents...</p>
  if (error) return <p className="dashboard">Error loading incidents: {error}</p>

  return (
    <div className="dashboard">
      <h2 className="section-title">
        Incidents
        <span className="count-pill">{incidents.length}</span>
      </h2>
      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Source IP</th>
              <th>Alerts</th>
              <th>MITRE Techniques</th>
              <th>Status</th>
              <th>First Seen</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((incident) => (
              <tr key={incident.id} onClick={() => onSelectIncident(incident.id)} className="clickable-row">
                <td>{incident.source_ip}</td>
                <td>{incident.alert_count}</td>
                <td>
                  <div className="badge-row">
                    {incident.mitre_techniques.map((t) => (
                      <MitreBadge key={t} technique={t} />
                    ))}
                  </div>
                </td>
                <td><span className={`status-pill status-${incident.status}`}>{incident.status}</span></td>
                <td>{new Date(incident.first_seen).toLocaleString()}</td>
                <td>{new Date(incident.last_seen).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function IncidentDetail({ incidentId, onBack, onSelectAlert }) {
  const [incident, setIncident] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch(`${API_BASE}/incidents/${incidentId}`)
      .then((res) => {
        if (!res.ok) throw new Error(`API returned ${res.status}`)
        return res.json()
      })
      .then((data) => {
        setIncident(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [incidentId])

  if (loading) return <p className="dashboard">Loading incident detail...</p>
  if (error) return <p className="dashboard">Error loading incident: {error}</p>

  return (
    <div className="dashboard">
      <button className="btn btn-back" onClick={onBack}>&larr; Back to incidents</button>
      <h2 style={{ marginBottom: '1.25rem' }}>Incident #{incident.id}</h2>

      <div className="meta-grid">
        <div className="meta-item">
          <span className="meta-label">Source IP</span>
          <span className="meta-value mono">{incident.source_ip}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">Status</span>
          <span className={`status-pill status-${incident.status}`}>{incident.status}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">MITRE Techniques</span>
          <div className="badge-row">
            {incident.mitre_techniques.map((t) => (
              <MitreBadge key={t} technique={t} />
            ))}
          </div>
        </div>
        <div className="meta-item">
          <span className="meta-label">First Seen</span>
          <span className="meta-value mono">{new Date(incident.first_seen).toLocaleString()}</span>
        </div>
        <div className="meta-item">
          <span className="meta-label">Last Seen</span>
          <span className="meta-value mono">{new Date(incident.last_seen).toLocaleString()}</span>
        </div>
      </div>

      <h3 style={{ marginBottom: '0.75rem' }}>Correlated Alerts ({incident.alerts.length})</h3>
      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Rule</th>
              <th>MITRE</th>
              <th>Username</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {incident.alerts.map((alert) => (
              <tr key={alert.id} onClick={() => onSelectAlert(alert.id)} className="clickable-row">
                <td>{new Date(alert.created_at).toLocaleString()}</td>
                <td><RuleBadge ruleName={alert.rule_name} /></td>
                <td><MitreBadge technique={alert.mitre_technique} /></td>
                <td>{alert.username || '—'}</td>
                <td>{alert.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function App() {
  const [view, setView] = useState('alerts')
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [selectedIncidentId, setSelectedIncidentId] = useState(null)

  const goToAlert = (id) => {
    setSelectedAlertId(id)
    setView('alert-detail')
  }

  const goToIncident = (id) => {
    setSelectedIncidentId(id)
    setView('incident-detail')
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          MINI <span className="brand-accent">SOC</span>
        </div>
        <div className="live-indicator">
          <span className="live-dot" />
          LIVE
        </div>
        <nav className="tabs">
          <button
            className={view.startsWith('alert') ? 'tab active' : 'tab'}
            onClick={() => setView('alerts')}
          >
            Alerts
          </button>
          <button
            className={view.startsWith('incident') ? 'tab active' : 'tab'}
            onClick={() => setView('incidents')}
          >
            Incidents
          </button>
        </nav>
      </header>

      <main>
        {view === 'alerts' && (
          <AlertsList onSelectAlert={goToAlert} onSelectIncident={goToIncident} />
        )}
        {view === 'alert-detail' && (
          <AlertDetail
            alertId={selectedAlertId}
            onBack={() => setView('alerts')}
            onSelectIncident={goToIncident}
          />
        )}
        {view === 'incidents' && <IncidentsList onSelectIncident={goToIncident} />}
        {view === 'incident-detail' && (
          <IncidentDetail
            incidentId={selectedIncidentId}
            onBack={() => setView('incidents')}
            onSelectAlert={goToAlert}
          />
        )}
      </main>
    </div>
  )
}

export default App
