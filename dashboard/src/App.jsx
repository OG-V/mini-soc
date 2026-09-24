import { useState, useEffect } from 'react'
import './App.css'

const API_BASE = 'http://localhost:8000'

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

    fetchAlerts() // initial load
    const intervalId = setInterval(fetchAlerts, 5000) // then poll every 5s

    return () => clearInterval(intervalId) // cleanup when component unmounts
  }, [])

  if (loading) return <p>Loading alerts...</p>
  if (error) return <p>Error loading alerts: {error}</p>

  return (
    <div className="dashboard">
      <h1>Mini SOC — Alerts</h1>
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
              <td>{alert.rule_name}</td>
              <td>{alert.mitre_technique}</td>
              <td>{alert.source_ip}</td>
              <td>{alert.username}</td>
              <td>{alert.description}</td>
              <td>
                {alert.incident_id ? (
                  <button
                    onClick={(e) => {
                      e.stopPropagation() // don't also trigger the row's onSelectAlert
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

  if (loading) return <p>Loading alert detail...</p>
  if (error) return <p>Error loading alert: {error}</p>

  return (
    <div className="dashboard">
      <button onClick={onBack}>&larr; Back to alerts</button>
      <h1>Alert #{alert.id}: {alert.rule_name}</h1>
      <p><strong>MITRE Technique:</strong> {alert.mitre_technique}</p>
      <p><strong>Source IP:</strong> {alert.source_ip}</p>
      <p><strong>Username:</strong> {alert.username}</p>
      <p><strong>Description:</strong> {alert.description}</p>
      <p><strong>Event count:</strong> {alert.event_count}</p>
      <p>
        <strong>Incident:</strong>{' '}
        {alert.incident_id ? (
          <button onClick={() => onSelectIncident(alert.incident_id)}>
            View incident #{alert.incident_id}
          </button>
        ) : (
          'Not correlated to an incident'
        )}
      </p>

      <h2>Timeline</h2>
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
              <td className="raw-log">{event.raw_log}</td>
            </tr>
          ))}
        </tbody>
      </table>
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

    fetchIncidents() // initial load
    const intervalId = setInterval(fetchIncidents, 5000) // then poll every 5s

    return () => clearInterval(intervalId)
  }, [])

  if (loading) return <p>Loading incidents...</p>
  if (error) return <p>Error loading incidents: {error}</p>

  return (
    <div className="dashboard">
      <h1>Mini SOC — Incidents</h1>
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
              <td>{incident.mitre_techniques.join(', ')}</td>
              <td>{incident.status}</td>
              <td>{new Date(incident.first_seen).toLocaleString()}</td>
              <td>{new Date(incident.last_seen).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
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

  if (loading) return <p>Loading incident detail...</p>
  if (error) return <p>Error loading incident: {error}</p>

  return (
    <div className="dashboard">
      <button onClick={onBack}>&larr; Back to incidents</button>
      <h1>Incident #{incident.id}</h1>
      <p><strong>Source IP:</strong> {incident.source_ip}</p>
      <p><strong>MITRE Techniques:</strong> {incident.mitre_techniques.join(', ')}</p>
      <p><strong>Status:</strong> {incident.status}</p>
      <p><strong>First seen:</strong> {new Date(incident.first_seen).toLocaleString()}</p>
      <p><strong>Last seen:</strong> {new Date(incident.last_seen).toLocaleString()}</p>

      <h2>Correlated Alerts ({incident.alerts.length})</h2>
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
              <td>{alert.rule_name}</td>
              <td>{alert.mitre_technique}</td>
              <td>{alert.username}</td>
              <td>{alert.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function App() {
  const [view, setView] = useState('alerts') // 'alerts' | 'alert-detail' | 'incidents' | 'incident-detail'
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
    <div>
      <nav className="tabs">
        <button onClick={() => setView('alerts')}>Alerts</button>
        <button onClick={() => setView('incidents')}>Incidents</button>
      </nav>

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
    </div>
  )
}

export default App
