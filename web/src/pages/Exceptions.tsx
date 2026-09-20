import { Button, Card, Space, Table, Tag, message } from 'antd'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { PageHeader } from '../components/PageHeader'
import { api } from '../lib/api'
import type { ExceptionRequest } from '../lib/types'
import { operationsKeys, useExceptions } from '../hooks/useOperations'

export function Exceptions({ canOperate }: { canOperate: boolean }) {
  const items = useExceptions()
  const queryClient = useQueryClient()
  const decide = useMutation({ mutationFn: ({ id, action }: { id: number; action: 'approve' | 'reject' }) => api(`/v1/admin/exceptions/${id}/${action}`, { method: 'POST', body: action === 'approve' ? JSON.stringify({ hours: 1 }) : undefined }), onSuccess: () => { message.success('审批结果已记录'); queryClient.invalidateQueries({ queryKey: operationsKeys.all }) }, onError: (error: Error) => message.error(error.message) })
  const statusMeta = { pending: ['待审批', 'orange'], approved: ['已批准', 'green'], rejected: ['已拒绝', 'red'] } as const
  return <><PageHeader eyebrow="Time-bound access" title="例外与审批" description="例外只绑定同一身份、目标和文件摘要，并在到期后自动失效。" />
    <Card className="section-card"><Table<ExceptionRequest> rowKey="id" loading={items.isLoading} dataSource={items.data ?? []} scroll={{ x: 900 }} columns={[
      { title: '申请', dataIndex: 'id', width: 90, render: value => `#${value}` },
      { title: '身份与目标', render: (_, item) => <div><strong>{item.actor}</strong><div className="cell-sub">→ {item.destination}</div></div> },
      { title: '业务理由', dataIndex: 'justification' },
      { title: '申请时间', dataIndex: 'created_at', render: value => new Date(value).toLocaleString('zh-CN', { hour12: false }) },
      { title: '状态', dataIndex: 'status', render: value => <Tag color={statusMeta[value as keyof typeof statusMeta][1]}>{statusMeta[value as keyof typeof statusMeta][0]}</Tag> },
      { title: '操作', width: 180, render: (_, item) => item.status === 'pending' ? <Space><Button size="small" type="primary" disabled={!canOperate} onClick={() => decide.mutate({ id: item.id, action: 'approve' })}>批准 1 小时</Button><Button size="small" danger disabled={!canOperate} onClick={() => decide.mutate({ id: item.id, action: 'reject' })}>拒绝</Button></Space> : <span className="muted">已完成</span> },
    ]} /></Card></>
}

