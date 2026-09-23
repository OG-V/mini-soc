import { useState, useEffect } from 'react'
import './App.css'

const API_BASE = 'http://localhost:8000'

function App() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
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
            <tr key={alert.id}>
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

export default App
