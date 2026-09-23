import { useState, useEffect } from 'react'
import './App.css'

const API_BASE = 'http://localhost:8000'

function AlertsList({ onSelectAlert }) {
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertDetail({ alertId, onBack }) {
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

function App() {
  const [selectedAlertId, setSelectedAlertId] = useState(null)

  if (selectedAlertId) {
    return <AlertDetail alertId={selectedAlertId} onBack={() => setSelectedAlertId(null)} />
  }

  return <AlertsList onSelectAlert={setSelectedAlertId} />
}

export default App
