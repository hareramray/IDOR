import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { scanApi } from '../api'

const defaultEndpoint = { path: '', method: 'GET', id_param: 'id', id_location: 'path', sample_id: '' }

const defaultCreds = {
  login_url: '/login',
  username_field: 'username',
  password_field: 'password',
  username: '',
  password: '',
  submit_selector: '',
  auth_type: 'form',
  bearer_token: '',
  extra_fields: {},
}

const SAMPLE_JSON = `{
  "name": "VulnVault local",
  "target_url": "http://127.0.0.1:5050",
  "user_a_credentials": {
    "auth_type": "form",
    "login_url": "/login",
    "username_field": "username",
    "password_field": "password",
    "username": "alice",
    "password": "alicepass"
  },
  "user_b_credentials": {
    "auth_type": "form",
    "login_url": "/login",
    "username_field": "username",
    "password_field": "password",
    "username": "bob",
    "password": "bobpass"
  },
  "admin_credentials": {
    "auth_type": "form",
    "login_url": "/login",
    "username_field": "username",
    "password_field": "password",
    "username": "admin",
    "password": "adminpass"
  },
  "endpoints": [
    { "path": "/api/notes/1", "method": "GET", "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/notes/1", "method": "PUT", "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/notes/1", "method": "DELETE", "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/users/1", "method": "GET", "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/invoices/1", "method": "GET", "id_param": "id", "id_location": "path", "sample_id": "1" },
    { "path": "/api/admin/users", "method": "GET", "id_location": "header" },
    { "path": "/api/secure/notes/1", "method": "GET", "id_param": "id", "id_location": "path", "sample_id": "1" }
  ]
}`

const mergeCreds = (raw) => ({ ...defaultCreds, ...(raw || {}) })

export default function NewScan() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const [name, setName] = useState('')
  const [targetUrl, setTargetUrl] = useState('')
  const [userA, setUserA] = useState({ ...defaultCreds })
  const [userB, setUserB] = useState({ ...defaultCreds })
  const [useAdmin, setUseAdmin] = useState(false)
  const [admin, setAdmin] = useState({ ...defaultCreds })
  const [endpoints, setEndpoints] = useState([{ ...defaultEndpoint }])
  const [config, setConfig] = useState({
    check_sequential: true,
    check_encoded_ids: true,
    check_uuid: true,
    test_no_auth: true,
    test_method_switch: true,
  })

  const [showJsonPanel, setShowJsonPanel] = useState(false)
  const [jsonText, setJsonText] = useState('')
  const [jsonError, setJsonError] = useState('')
  const [jsonNotice, setJsonNotice] = useState('')

  const applyJson = () => {
    setJsonError('')
    setJsonNotice('')
    let parsed
    try {
      parsed = JSON.parse(jsonText)
    } catch (e) {
      setJsonError(`Invalid JSON: ${e.message}`)
      return
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      setJsonError('JSON must be an object')
      return
    }
    if (parsed.name !== undefined) setName(String(parsed.name))
    if (parsed.target_url !== undefined) setTargetUrl(String(parsed.target_url))
    if (parsed.user_a_credentials) setUserA(mergeCreds(parsed.user_a_credentials))
    if (parsed.user_b_credentials) setUserB(mergeCreds(parsed.user_b_credentials))
    if (parsed.admin_credentials) {
      setAdmin(mergeCreds(parsed.admin_credentials))
      setUseAdmin(true)
    } else if (parsed.admin_credentials === null) {
      setUseAdmin(false)
    }
    if (Array.isArray(parsed.endpoints)) {
      const eps = parsed.endpoints
        .filter(ep => ep && typeof ep === 'object')
        .map(ep => ({ ...defaultEndpoint, ...ep, sample_id: ep.sample_id ? String(ep.sample_id) : '' }))
      setEndpoints(eps.length ? eps : [{ ...defaultEndpoint }])
    }
    if (parsed.config && typeof parsed.config === 'object') {
      setConfig(prev => ({ ...prev, ...parsed.config }))
    }
    setJsonNotice('Loaded into form. Review and Launch when ready.')
  }

  const exportJson = () => {
    const payload = {
      name: name || `Scan - ${new Date().toLocaleString()}`,
      target_url: targetUrl,
      user_a_credentials: userA,
      user_b_credentials: userB,
      admin_credentials: useAdmin ? admin : null,
      endpoints: endpoints.filter(ep => ep.path.trim()),
      config,
    }
    setJsonText(JSON.stringify(payload, null, 2))
    setJsonError('')
    setJsonNotice('Exported current form state.')
  }

  const loadSample = () => {
    setJsonText(SAMPLE_JSON)
    setJsonError('')
    setJsonNotice('Sample loaded. Click "Apply JSON" to populate the form.')
  }

  const updateEndpoint = (i, field, value) => {
    const updated = [...endpoints]
    updated[i] = { ...updated[i], [field]: value }
    setEndpoints(updated)
  }

  const addEndpoint = () => setEndpoints([...endpoints, { ...defaultEndpoint }])
  const removeEndpoint = (i) => setEndpoints(endpoints.filter((_, idx) => idx !== i))

  const updateCreds = (setter, field, value) => {
    setter(prev => ({ ...prev, [field]: value }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const payload = {
        name: name || `Scan - ${new Date().toLocaleString()}`,
        target_url: targetUrl,
        user_a_credentials: userA,
        user_b_credentials: userB,
        admin_credentials: useAdmin ? admin : null,
        endpoints: endpoints.filter(ep => ep.path.trim()),
        config,
      }

      const { data: scan } = await scanApi.create(payload)
      await scanApi.start(scan.id)
      navigate(`/scan/${scan.id}`)
    } catch (err) {
      const detail = err.response?.data
      setError(typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const CredentialForm = ({ creds, setCreds, title }) => (
    <div className="form-section">
      <h3>{title}</h3>
      <div className="form-group">
        <label>Auth Type</label>
        <select value={creds.auth_type} onChange={e => updateCreds(setCreds, 'auth_type', e.target.value)}>
          <option value="form">Form Login</option>
          <option value="bearer">Bearer Token</option>
          <option value="custom">Custom Headers</option>
        </select>
      </div>

      {creds.auth_type === 'bearer' ? (
        <div className="form-group">
          <label>Bearer Token</label>
          <input
            type="text"
            value={creds.bearer_token}
            onChange={e => updateCreds(setCreds, 'bearer_token', e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIs..."
          />
        </div>
      ) : creds.auth_type === 'custom' ? (
        <div className="form-group">
          <label>Custom Headers (JSON)</label>
          <textarea
            value={typeof creds.custom_headers === 'string' ? creds.custom_headers : JSON.stringify(creds.custom_headers || {}, null, 2)}
            onChange={e => updateCreds(setCreds, 'custom_headers', e.target.value)}
            placeholder='{"X-API-Key": "your-key"}'
          />
        </div>
      ) : (
        <>
          <div className="form-row">
            <div className="form-group">
              <label>Login URL</label>
              <input
                value={creds.login_url}
                onChange={e => updateCreds(setCreds, 'login_url', e.target.value)}
                placeholder="/login"
              />
            </div>
            <div className="form-group">
              <label>Submit Selector (optional)</label>
              <input
                value={creds.submit_selector}
                onChange={e => updateCreds(setCreds, 'submit_selector', e.target.value)}
                placeholder='button[type="submit"]'
              />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Username Field (name or CSS selector)</label>
              <input
                value={creds.username_field}
                onChange={e => updateCreds(setCreds, 'username_field', e.target.value)}
                placeholder="username"
              />
            </div>
            <div className="form-group">
              <label>Password Field (name or CSS selector)</label>
              <input
                value={creds.password_field}
                onChange={e => updateCreds(setCreds, 'password_field', e.target.value)}
                placeholder="password"
              />
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Username</label>
              <input
                value={creds.username}
                onChange={e => updateCreds(setCreds, 'username', e.target.value)}
                placeholder="user1"
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                value={creds.password}
                onChange={e => updateCreds(setCreds, 'password', e.target.value)}
                placeholder="password"
              />
            </div>
          </div>
        </>
      )}
    </div>
  )

  return (
    <div>
      <h2 className="mb-4">New IDOR Scan</h2>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header" style={{ marginBottom: showJsonPanel ? 12 : 0 }}>
          <h3 style={{ margin: 0 }}>Import / Export via JSON</h3>
          <div style={{ display: 'flex', gap: 8 }}>
            {showJsonPanel && (
              <button type="button" className="btn btn-sm btn-outline" onClick={loadSample}>
                Load sample
              </button>
            )}
            <button
              type="button"
              className="btn btn-sm btn-outline"
              onClick={() => setShowJsonPanel(v => !v)}
            >
              {showJsonPanel ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>
        {showJsonPanel && (
          <>
            <p className="text-sm" style={{ color: 'var(--text-muted)', marginBottom: 8 }}>
              Paste a scan config (same shape as the API payload) and click <b>Apply JSON</b>.
              Fields not present in the JSON keep their current values.
            </p>
            <textarea
              value={jsonText}
              onChange={e => setJsonText(e.target.value)}
              placeholder={SAMPLE_JSON}
              spellCheck={false}
              style={{
                width: '100%',
                minHeight: 240,
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                fontSize: 12,
              }}
            />
            <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
              <button type="button" className="btn btn-primary btn-sm" onClick={applyJson}>
                Apply JSON
              </button>
              <button type="button" className="btn btn-outline btn-sm" onClick={exportJson}>
                Export current form
              </button>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => { setJsonText(''); setJsonError(''); setJsonNotice('') }}
              >
                Clear
              </button>
            </div>
            {jsonError && (
              <pre
                className="text-sm"
                style={{ color: 'var(--danger)', whiteSpace: 'pre-wrap', marginTop: 8 }}
              >
                {jsonError}
              </pre>
            )}
            {jsonNotice && !jsonError && (
              <div className="text-sm" style={{ color: 'var(--success)', marginTop: 8 }}>
                {jsonNotice}
              </div>
            )}
          </>
        )}
      </div>

      {error && (
        <div className="card" style={{ borderColor: 'var(--danger)', marginBottom: 16 }}>
          <pre className="text-sm" style={{ color: 'var(--danger)', whiteSpace: 'pre-wrap' }}>{error}</pre>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        {/* Basic Info */}
        <div className="card">
          <div className="form-row">
            <div className="form-group">
              <label>Scan Name</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="My IDOR Test"
              />
            </div>
            <div className="form-group">
              <label>Target URL *</label>
              <input
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://target-app.com"
                required
              />
            </div>
          </div>
        </div>

        {/* User Credentials */}
        <CredentialForm creds={userA} setCreds={setUserA} title="User A Credentials (Victim)" />
        <CredentialForm creds={userB} setCreds={setUserB} title="User B Credentials (Attacker)" />

        {/* Admin (optional) */}
        <div className="card">
          <label className="flex items-center gap-2" style={{ cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={useAdmin}
              onChange={e => setUseAdmin(e.target.checked)}
              style={{ width: 'auto' }}
            />
            Enable Vertical IDOR Testing (Admin credentials)
          </label>
        </div>
        {useAdmin && (
          <CredentialForm creds={admin} setCreds={setAdmin} title="Admin Credentials (Vertical Testing)" />
        )}

        {/* Endpoints */}
        <div className="card">
          <div className="card-header">
            <h2>Endpoints to Test</h2>
            <button type="button" className="btn btn-sm btn-outline" onClick={addEndpoint}>
              + Add Endpoint
            </button>
          </div>

          <div className="endpoint-row" style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-muted)' }}>
            <span>METHOD</span>
            <span>PATH</span>
            <span>ID PARAM</span>
            <span>ID LOCATION</span>
            <span></span>
          </div>

          {endpoints.map((ep, i) => (
            <div className="endpoint-row" key={i}>
              <select value={ep.method} onChange={e => updateEndpoint(i, 'method', e.target.value)}>
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>PATCH</option>
                <option>DELETE</option>
              </select>
              <input
                value={ep.path}
                onChange={e => updateEndpoint(i, 'path', e.target.value)}
                placeholder="/api/users/{id}/profile"
                required
              />
              <input
                value={ep.id_param}
                onChange={e => updateEndpoint(i, 'id_param', e.target.value)}
                placeholder="id"
              />
              <select value={ep.id_location} onChange={e => updateEndpoint(i, 'id_location', e.target.value)}>
                <option value="path">Path</option>
                <option value="query">Query</option>
                <option value="body">Body</option>
                <option value="header">Header</option>
              </select>
              <button type="button" className="remove-btn" onClick={() => removeEndpoint(i)} title="Remove">
                &times;
              </button>
            </div>
          ))}

          {endpoints.map((ep, i) => (
            <div key={`sample-${i}`} className="form-group" style={{ marginTop: 8 }}>
              <label>Sample ID for {ep.path || `Endpoint ${i + 1}`} (optional)</label>
              <input
                value={ep.sample_id}
                onChange={e => updateEndpoint(i, 'sample_id', e.target.value)}
                placeholder="e.g., 123 or 550e8400-e29b-41d4-a716-446655440000"
              />
            </div>
          ))}
        </div>

        {/* Config */}
        <div className="card">
          <h2 style={{ marginBottom: 16 }}>Test Configuration</h2>
          <div className="form-row">
            {Object.entries(config).map(([key, val]) => (
              <label key={key} className="flex items-center gap-2" style={{ cursor: 'pointer', marginBottom: 8 }}>
                <input
                  type="checkbox"
                  checked={val}
                  onChange={e => setConfig({ ...config, [key]: e.target.checked })}
                  style={{ width: 'auto' }}
                />
                {key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
              </label>
            ))}
          </div>
        </div>

        <button type="submit" className="btn btn-primary" disabled={loading} style={{ width: '100%', justifyContent: 'center', padding: '14px' }}>
          {loading ? <><div className="spinner" /> Starting Scan...</> : 'Launch IDOR Scan'}
        </button>
      </form>
    </div>
  )
}
