import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { scanApi } from '../api'

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export default function ScanDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [logs, setLogs] = useState([])
  const [tab, setTab] = useState('overview')
  const [severityFilter, setSeverityFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const logEndRef = useRef(null)
  const lastLogTime = useRef(null)

  const fetchScan = async () => {
    try {
      const { data } = await scanApi.get(id)
      setScan(data)
      if (data.logs) setLogs(data.logs)
    } catch {
      navigate('/')
    } finally {
      setLoading(false)
    }
  }

  const pollLogs = async () => {
    try {
      const params = lastLogTime.current ? { after: lastLogTime.current } : {}
      const { data: newLogs } = await scanApi.logs(id, lastLogTime.current)
      if (newLogs.length > 0) {
        setLogs(prev => [...prev, ...newLogs])
        lastLogTime.current = newLogs[newLogs.length - 1].created_at
      }
    } catch {}
  }

  useEffect(() => {
    fetchScan()
    const interval = setInterval(() => {
      fetchScan()
      pollLogs()
    }, 3000)
    return () => clearInterval(interval)
  }, [id])

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs])

  const handleStart = async () => {
    await scanApi.start(id)
    fetchScan()
  }

  const handleCancel = async () => {
    await scanApi.cancel(id)
    fetchScan()
  }

  if (loading || !scan) {
    return <div className="empty-state"><div className="spinner" /></div>
  }

  const findings = scan.findings || []
  const vulnFindings = findings.filter(f => f.is_vulnerable)
  const filteredFindings = severityFilter
    ? findings.filter(f => f.severity === severityFilter)
    : findings
  const sortedFindings = [...filteredFindings].sort(
    (a, b) => (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5)
  )

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <button className="btn btn-sm btn-outline" onClick={() => navigate('/')} style={{ marginBottom: 8 }}>
            &larr; Back
          </button>
          <h2>{scan.name}</h2>
          <p className="text-sm text-muted">{scan.target_url}</p>
        </div>
        <div className="flex gap-2">
          {scan.status === 'pending' && (
            <button className="btn btn-primary" onClick={handleStart}>Start Scan</button>
          )}
          {scan.status === 'running' && (
            <button className="btn btn-danger" onClick={handleCancel}>Cancel</button>
          )}
          <span className={`badge badge-${scan.status}`}>{scan.status}</span>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div className={`stat-value ${scan.status === 'completed' ? 'success' : 'accent'}`}>
            {scan.status === 'running' && <span className="spinner" style={{ marginRight: 8 }} />}
            {scan.status.toUpperCase()}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Tests</div>
          <div className="stat-value accent">{scan.total_tests}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Vulnerabilities</div>
          <div className={`stat-value ${scan.vulnerabilities_found > 0 ? 'critical' : 'success'}`}>
            {scan.vulnerabilities_found}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Critical/High</div>
          <div className="stat-value critical">
            {vulnFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        <button className={`tab ${tab === 'overview' ? 'active' : ''}`} onClick={() => setTab('overview')}>
          Findings ({vulnFindings.length})
        </button>
        <button className={`tab ${tab === 'all' ? 'active' : ''}`} onClick={() => setTab('all')}>
          All Results ({findings.length})
        </button>
        <button className={`tab ${tab === 'logs' ? 'active' : ''}`} onClick={() => setTab('logs')}>
          Live Logs ({logs.length})
        </button>
      </div>

      {/* Findings */}
      {(tab === 'overview' || tab === 'all') && (
        <div>
          <div className="flex items-center gap-2 mb-4">
            <span className="text-sm text-muted">Filter:</span>
            {['', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
              <button
                key={s}
                className={`btn btn-sm ${severityFilter === s ? 'btn-primary' : 'btn-outline'}`}
                onClick={() => setSeverityFilter(s)}
              >
                {s || 'All'}
              </button>
            ))}
          </div>

          {(tab === 'overview' ? sortedFindings.filter(f => f.is_vulnerable) : sortedFindings)
            .map(finding => (
              <FindingCard key={finding.id} finding={finding} />
            ))}

          {sortedFindings.length === 0 && (
            <div className="empty-state">
              <h3>{scan.status === 'running' ? 'Scan in progress...' : 'No findings'}</h3>
              <p>
                {scan.status === 'running'
                  ? 'Results will appear here as the scan progresses.'
                  : 'No vulnerabilities were detected.'}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Logs */}
      {tab === 'logs' && (
        <div className="log-viewer">
          {logs.length === 0 && (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: 40 }}>
              {scan.status === 'running' ? 'Waiting for logs...' : 'No logs available.'}
            </div>
          )}
          {logs.map((log, i) => (
            <div className="log-entry" key={log.id || i}>
              <span className="log-time">
                {new Date(log.created_at).toLocaleTimeString()}
              </span>
              <span className={`log-level ${log.level}`}>{log.level}</span>
              <span className="log-message">{log.message}</span>
            </div>
          ))}
          <div ref={logEndRef} />
        </div>
      )}
    </div>
  )
}

function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)

  let analysis = {}
  try {
    analysis = JSON.parse(finding.ai_analysis || '{}')
  } catch {}

  return (
    <div
      className={`card finding-detail ${finding.severity}`}
      style={{ cursor: 'pointer' }}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
          <span style={{ fontWeight: 600 }}>{finding.method} {finding.endpoint}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`badge badge-${finding.is_vulnerable ? 'high' : 'info'}`}>
            {finding.is_vulnerable ? 'VULNERABLE' : 'SAFE'}
          </span>
          <span className="text-sm text-muted">{finding.idor_type}</span>
          <span style={{ fontSize: 18 }}>{expanded ? '▾' : '▸'}</span>
        </div>
      </div>

      {expanded && (
        <div className="mt-4">
          <p className="text-sm" style={{ marginBottom: 12 }}>{finding.description}</p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <span className="text-sm text-muted">Original ID</span>
              <div className="evidence-block">{finding.original_id || 'N/A'}</div>
            </div>
            <div>
              <span className="text-sm text-muted">Tested ID</span>
              <div className="evidence-block">{finding.tested_id || 'N/A'}</div>
            </div>
          </div>

          {finding.evidence && (
            <div>
              <span className="text-sm text-muted">Evidence</span>
              <div className="evidence-block">
                {JSON.stringify(finding.evidence, null, 2)}
              </div>
            </div>
          )}

          {finding.remediation && (
            <div className="mt-2">
              <span className="text-sm text-muted">Remediation</span>
              <p className="text-sm mt-2" style={{ color: 'var(--success)' }}>{finding.remediation}</p>
            </div>
          )}

          {analysis.confidence && (
            <div className="mt-2 text-sm text-muted">
              AI Confidence: <strong>{analysis.confidence}</strong>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
