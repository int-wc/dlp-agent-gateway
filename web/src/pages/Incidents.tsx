import { SyncOutlined } from '@ant-design/icons'
import { Button } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import { IncidentWorkbench } from '../components/IncidentWorkbench'
import { PageHeader } from '../components/PageHeader'
import { operationsKeys, useAudits, useExceptions, useFeedback, useIncidents } from '../hooks/useOperations'

export function Incidents({ canOperate }: { canOperate: boolean }) {
  const audits = useAudits()
  const feedback = useFeedback()
  const incidents = useIncidents()
  const exceptions = useExceptions()
  const queryClient = useQueryClient()
  const refreshing = audits.isFetching || feedback.isFetching || exceptions.isFetching || incidents.isFetching
  return <><PageHeader eyebrow="Investigation workspace" title="事件中心" description="从风险队列进入证据链、关联活动与人工处置，所有结论都保留在审计记录中。" extra={<Button icon={<SyncOutlined spin={refreshing} />} onClick={() => queryClient.invalidateQueries({ queryKey: operationsKeys.all })}>刷新数据</Button>} />
    <IncidentWorkbench audits={audits.data ?? []} feedback={feedback.data ?? []} incidents={incidents.data ?? []} exceptions={exceptions.data ?? []} loading={audits.isLoading || feedback.isLoading || incidents.isLoading || exceptions.isLoading} canOperate={canOperate} />
  </>
}
