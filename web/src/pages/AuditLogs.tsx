import { useState } from 'react'
import { Button, Card, message } from 'antd'
import { DownloadOutlined } from '@ant-design/icons'
import { AuditTable } from '../components/AuditTable'
import { PageHeader } from '../components/PageHeader'
import { useAuditPage } from '../hooks/useOperations'
import { downloadAuditCSV } from '../lib/api'
import type { AuditQuery } from '../lib/types'

export function AuditLogs({ canOperate }: { canOperate: boolean }) {
  const [query, setQuery] = useState<AuditQuery>({ page: 1, pageSize: 20, action: 'all', search: '', window: '7d' })
  const [exporting, setExporting] = useState(false)
  const audits = useAuditPage(query)
  const exportCurrent = async () => {
    setExporting(true)
    try { await downloadAuditCSV(query); message.success('筛选结果已导出') }
    catch (error) { message.error((error as Error).message) }
    finally { setExporting(false) }
  }
  return <><PageHeader title="审计日志" description="按时间、判定和关键字检索内容决策与传输结果。" extra={<Button icon={<DownloadOutlined />} loading={exporting} onClick={exportCurrent}>导出筛选结果</Button>} />
    <Card className="section-card"><AuditTable audits={audits.data?.items ?? []} total={audits.data?.total ?? 0} query={query} onQueryChange={change => setQuery(current => ({ ...current, ...change }))} loading={audits.isLoading || audits.isFetching} canOperate={canOperate} /></Card></>
}
