import type { ReactNode } from 'react'
import { Card } from 'antd'

export function MetricCard({ label, value, note, tone = 'neutral', icon, suffix }: { label: string; value: ReactNode; note: string; tone?: string; icon: ReactNode; suffix?: ReactNode }) {
  return <Card className={`metric-card metric-${tone}`}>
    <div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div>
    <div className="metric-value">{value}{suffix && <small>{suffix}</small>}</div>
    <div className="metric-note">{note}</div>
  </Card>
}
