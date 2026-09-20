import { Card } from 'antd'
import { AuditTable } from '../components/AuditTable'
import { PageHeader } from '../components/PageHeader'
import { useAudits } from '../hooks/useOperations'

export function AuditLogs({ canOperate }: { canOperate: boolean }) {
  const audits = useAudits()
  return <><PageHeader eyebrow="Evidence ledger" title="审计日志" description="查看内容判定与传输结果。两者始终分开记录，避免把“允许”误认为“已发送”。" />
    <Card className="section-card"><AuditTable audits={audits.data ?? []} loading={audits.isLoading} canOperate={canOperate} /></Card></>
}

