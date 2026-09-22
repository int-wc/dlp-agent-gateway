import type { AdminEvent, Audit, AuditPage, AuditQuery, DestinationInfo, ExceptionRequest, Feedback, Health, Incident, IncidentNote, Policy, Report, Session, UserRisk } from './types'

let adminToken = ''

export function setAdminToken(value: string) {
  adminToken = value.trim()
}

export class APIError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  const data = await response.json().catch(() => ({ detail: 'invalid_response' }))
  if (!response.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : data.detail?.reason ?? JSON.stringify(data.detail)
    throw new APIError(response.status, detail || 'request_failed')
  }
  return data as T
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (adminToken) headers.set('Authorization', 'Bearer ' + adminToken)
  if (options.body && typeof options.body === 'string') headers.set('Content-Type', 'application/json')
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' })
  return parseResponse<T>(response)
}

export const getHealth = () => api<Health>('/health')
export const getSession = () => api<Session>('/v1/auth/session')
export const getAudits = (limit = 500) => api<Audit[]>(`/v1/admin/audits?limit=${limit}`)
function auditQueryString(query: AuditQuery) {
  const params = new URLSearchParams({ page: String(query.page), page_size: String(query.pageSize), window: query.window })
  if (query.action !== 'all') params.set('action', query.action)
  if (query.search.trim()) params.set('q', query.search.trim())
  return params.toString()
}
export const getAuditPage = (query: AuditQuery) => api<AuditPage>(`/v1/admin/audits/query?${auditQueryString(query)}`)
export async function downloadAuditCSV(query: AuditQuery) {
  const response = await fetch(`/v1/admin/audits/export?${auditQueryString(query)}`, { headers: adminToken ? { Authorization: 'Bearer ' + adminToken } : {}, credentials: 'same-origin' })
  if (!response.ok) return parseResponse<never>(response)
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `dlp-audits-${new Date().toISOString().slice(0, 10)}.csv`
  anchor.click()
  URL.revokeObjectURL(url)
}
export const getPolicies = () => api<Policy[]>('/v1/admin/policies')
export const getUsers = () => api<UserRisk[]>('/v1/admin/users')
export const getExceptions = () => api<ExceptionRequest[]>('/v1/admin/exceptions')
export const getFeedback = () => api<Feedback[]>('/v1/admin/feedback')
export const getIncidents = () => api<Incident[]>('/v1/admin/incidents')
export const getIncidentNotes = (auditID: number) => api<IncidentNote[]>(`/v1/admin/incidents/${auditID}/notes`)
export const getReport = (days: number) => api<Report>(`/v1/admin/report?days=${days}`)
export const getEvents = () => api<AdminEvent[]>('/v1/admin/events')

export async function clientJSON<T>(path: string, token: string): Promise<T> {
  const response = await fetch(path, { headers: { Authorization: 'Bearer ' + token }, credentials: 'same-origin' })
  return parseResponse<T>(response)
}

export async function inspectFile(token: string, destination: string, mode: 'check' | 'forward', file: File) {
  const body = new FormData()
  body.append('file', file)
  const response = await fetch(`/v1/${mode}/${encodeURIComponent(destination)}`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + token }, body, credentials: 'same-origin',
  })
  return parseResponse<Record<string, unknown>>(response)
}

export type { DestinationInfo }
