import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { scanApi } from '../api'

export default function Dashboard() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchScans = async () => {
    try {
      const { data } = await scanApi.list()
      setScans(data)
    } catch (err) {
      console.error('Failed to fetch scans:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchScans()
    const interval = setInterval(fetchScans, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleDelete = async (e, id) => {
    e.preventDefault()
    e.stopPropagation()
    if (!confirm('Delete this scan?')) return
    await scanApi.delete(id)
    fetchScans()
  }

  const handleRerun = async (e, id) => {
    e.preventDefault()
    e.stopPropagation()
    if (!confirm('Rerun this scan? Existing findings and logs will be cleared.')) return
    await scanApi.rerun(id)
    fetchScans()
  }

  if (loading) {
    return <div className="empty-state"><div className="spinner" /></div>
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2>Scan History</h2>
        <Link to="/new" className="btn btn-primary">+ New Scan</Link>
      </div>

      {scans.length === 0 ? (
        <div className="empty-state">
          <h3>No scans yet</h3>
          <p>Create your first IDOR scan to get started.</p>
          <Link to="/new" className="btn btn-primary mt-4">Create Scan</Link>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Target</th>
                <th>Status</th>
                <th>Tests</th>
                <th>Vulnerabilities</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.id} onClick={() => window.location.href = `/scan/${scan.id}`}>
                  <td style={{ fontWeight: 600 }}>{scan.name}</td>
                  <td className="text-sm text-muted">{scan.target_url}</td>
                  <td>
                    <span className={`badge badge-${scan.status}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>{scan.total_tests}</td>
                  <td>
                    <span style={{ color: scan.vulnerabilities_found > 0 ? 'var(--danger)' : 'var(--success)', fontWeight: 600 }}>
                      {scan.vulnerabilities_found}
                    </span>
                  </td>
                  <td className="text-sm text-muted">
                    {new Date(scan.created_at).toLocaleDateString()}
                  </td>
                  <td>
                    <div className="flex gap-2">
                      {(scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') && (
                        <button className="btn btn-sm btn-outline" onClick={(e) => handleRerun(e, scan.id)}>
                          Rerun
                        </button>
                      )}
                      <button className="btn btn-sm btn-outline" onClick={(e) => handleDelete(e, scan.id)}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
