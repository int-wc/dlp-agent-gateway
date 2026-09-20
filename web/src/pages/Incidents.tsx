import { Card } from 'antd'
import { AuditTable } from '../components/AuditTable'
import { PageHeader } from '../components/PageHeader'
import { useAudits } from '../hooks/useOperations'

export function Incidents({ canOperate }: { canOperate: boolean }) {
  const audits = useAudits()
  return <><PageHeader eyebrow="Triage queue" title="事件中心" description="集中处理待复核和已阻断事件，保留每一次人工判断。" />
    <Card className="section-card"><AuditTable audits={audits.data ?? []} loading={audits.isLoading} incidentsOnly canOperate={canOperate} /></Card></>
}

