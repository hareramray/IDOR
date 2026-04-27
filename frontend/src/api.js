import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
})

export const scanApi = {
  list: () => api.get('/scans/'),
  get: (id) => api.get(`/scans/${id}/`),
  create: (data) => api.post('/scans/', data),
  start: (id) => api.post(`/scans/${id}/start/`),
  rerun: (id) => api.post(`/scans/${id}/rerun/`),
  cancel: (id) => api.post(`/scans/${id}/cancel/`),
  delete: (id) => api.delete(`/scans/${id}/`),
  findings: (id, severity) => {
    const params = severity ? { severity } : {}
    return api.get(`/scans/${id}/findings/`, { params })
  },
  logs: (id, after) => {
    const params = after ? { after } : {}
    return api.get(`/scans/${id}/logs/`, { params })
  },
}

export const findingApi = {
  list: (params) => api.get('/findings/', { params }),
  get: (id) => api.get(`/findings/${id}/`),
}

export default api
