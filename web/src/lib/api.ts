import type { AdminEvent, Audit, DestinationInfo, ExceptionRequest, Feedback, Health, Policy, Report, Session, UserRisk } from './types'

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
export const getPolicies = () => api<Policy[]>('/v1/admin/policies')
export const getUsers = () => api<UserRisk[]>('/v1/admin/users')
export const getExceptions = () => api<ExceptionRequest[]>('/v1/admin/exceptions')
export const getFeedback = () => api<Feedback[]>('/v1/admin/feedback')
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
