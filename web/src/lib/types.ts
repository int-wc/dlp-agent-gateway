export type Action = 'allow' | 'review' | 'block'

export interface Audit {
  id: number
  created_at: string
  actor: string
  destination: string
  filename: string
  sha256: string
  size: number
  action: Action
  reasons: string[]
  signals: string[]
  model_status: string
  forwarded: boolean
  transfer_status: string
  upstream_status?: number
}

export interface Policy {
  id: number
  keyword: string
  action: 'review' | 'block'
  scope: 'all' | 'internal' | 'external'
  mode: 'draft' | 'monitor' | 'enforce'
  enabled: boolean
}

export interface ExceptionRequest {
  id: number
  audit_id: number
  actor: string
  destination: string
  sha256: string
  justification: string
  status: 'pending' | 'approved' | 'rejected'
  created_at: string
  expires_at?: string
}

export interface Feedback {
  audit_id: number
  verdict: 'true_positive' | 'false_positive'
  note: string
  created_at: string
}

export type IncidentStatus = 'new' | 'investigating' | 'pending_business' | 'resolved'

export interface Incident {
  audit_id: number
  status: IncidentStatus
  assignee: string
  updated_at: string
}

export interface IncidentNote {
  id: number
  audit_id: number
  author: string
  body: string
  created_at: string
}

export interface AdminEvent {
  id: number
  created_at: string
  event: string
  target: string
}

export interface UserRisk {
  actor: string
  status: 'normal' | 'privileged' | 'departing'
}

export interface Report {
  days: number
  total: number
  counts: Record<Action, number>
  transfer_counts: Record<string, number>
  daily_counts: Record<string, Record<Action, number>>
  top_reasons: Record<string, number>
  false_positive_policy_candidates: Record<string, number>
  operations: {
    active_risks: number
    remediated: number
    false_positives: number
    mean_time_to_remediate_seconds: number | null
    inspection_coverage_percent: number | null
    high_risk_users: number
    active_detectors: number
  }
  note: string
}

export interface Health {
  status: string
  version: string
  analyzer_enabled: boolean
  model_enabled: boolean
  storage: string
  oidc_enabled: boolean
  mtls_required: boolean
}

export interface Identity {
  subject: string
  name?: string
  email?: string
  role: 'admin' | 'operator' | 'viewer'
}

export interface Session {
  authenticated: boolean
  mode: 'static' | 'oidc' | 'oidc_or_static'
  identity?: Identity
}

export interface DestinationInfo {
  kind: 'internal' | 'external'
  forwarding_configured: boolean
  upstream_auth: 'none' | 'bearer' | 'mtls'
}
