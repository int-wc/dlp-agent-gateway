import { useMemo, useState } from 'react'
import { Button, Descriptions, Drawer, Empty, Input, Select, Space, Table, Tag, message } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Action, Audit } from '../lib/types'
import { operationsKeys } from '../hooks/useOperations'

export const actionMeta: Record<Action, { label: string; color: string }> = {
  allow: { label: '允许', color: 'green' }, review: { label: '待复核', color: 'orange' }, block: { label: '已阻断', color: 'red' },
}
export const transferLabels: Record<string, string> = {
  not_requested: '未请求', not_attempted: '未尝试', pending: '处理中', not_configured: '未配置', failed: '失败', forwarded: '已转发',
}
export const reasonLabel = (value: string) => {
  const labels: Record<string, string> = {
    private_key: '私钥特征', aws_access_key: '云凭据特征', phone_candidate: '手机号候选', id_candidate: '身份号码候选',
    departing_user: '离职人员', privileged_external: '重点岗位外发', unsupported_format: '格式未覆盖', analyzer_unavailable: '解析服务不可用',
    model_unavailable: '模型不可用', blank_content: '未提取到内容', file_too_large: '文件超限', unparseable_or_unsupported: '格式未完整解析',
    departing_external: '离职人员外发', secret_external: '密钥材料外发', personal_data_candidate: '个人信息候选',
    model_risk_medium: '模型中风险', model_risk_high: '模型高风险',
  }
  if (value.startsWith('policy_')) return `策略 #${value.slice(7)}`
  return labels[value] ?? value.replaceAll('_', ' ')
}
export const formatBytes = (value: number) => value >= 1024 * 1024 ? `${(value / 1024 / 1024).toFixed(1)} MB` : value >= 1024 ? `${(value / 1024).toFixed(1)} KB` : `${value} B`
export const formatDateTime = (value: string, part?: 'date' | 'time') => {
  const date = new Date(value)
  if (part === 'date') return date.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' })
  if (part === 'time') return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })
  return date.toLocaleString('zh-CN', { hour12: false })
}

export function AuditTable({ audits, loading, incidentsOnly = false, canOperate = true }: { audits: Audit[]; loading: boolean; incidentsOnly?: boolean; canOperate?: boolean }) {
  const [selected, setSelected] = useState<Audit | null>(null)
  const [search, setSearch] = useState('')
  const [action, setAction] = useState<Action | 'all'>('all')
  const queryClient = useQueryClient()
  const feedback = useMutation({
    mutationFn: (id: number) => api(`/v1/admin/audits/${id}/feedback`, { method: 'PUT', body: JSON.stringify({ verdict: 'false_positive', note: '运营台人工反馈' }) }),
    onSuccess: () => { message.success('已记录误报反馈'); queryClient.invalidateQueries({ queryKey: operationsKeys.all }) },
    onError: (error: Error) => message.error(error.message),
  })
  const data = useMemo(() => audits.filter(item => {
    if (incidentsOnly && item.action === 'allow') return false
    if (action !== 'all' && item.action !== action) return false
    const text = [item.actor, item.destination, item.filename, ...item.reasons].join(' ').toLowerCase()
    return text.includes(search.toLowerCase())
  }), [audits, search, action, incidentsOnly])

  return <>
    <div className="table-toolbar">
      <Input allowClear prefix={<SearchOutlined />} placeholder="搜索身份、目标、文件或命中原因" value={search} onChange={event => setSearch(event.target.value)} />
      <Select value={action} onChange={setAction} options={[{ value: 'all', label: '全部判定' }, { value: 'review', label: '待复核' }, { value: 'block', label: '已阻断' }, { value: 'allow', label: '允许' }]} />
    </div>
    <Table<Audit> rowKey="id" loading={loading} dataSource={data} pagination={{ pageSize: 12, showSizeChanger: false, showTotal: total => `共 ${total} 条` }} scroll={{ x: 980 }} locale={{ emptyText: <Empty description="暂无符合条件的审计事件" /> }} onRow={record => ({ onClick: () => setSelected(record) })} columns={[
      { title: '风险', dataIndex: 'action', width: 100, render: (value: Action) => <Tag color={actionMeta[value].color}>{actionMeta[value].label}</Tag> },
      { title: '时间', dataIndex: 'created_at', width: 176, render: value => formatDateTime(value) },
      { title: '身份与目标', width: 190, render: (_, item) => <div><strong>{item.actor}</strong><div className="cell-sub">→ {item.destination}</div></div> },
      { title: '文件', dataIndex: 'filename', ellipsis: true, render: (value, item) => <div><span>{value}</span><div className="cell-sub">{formatBytes(item.size)}</div></div> },
      { title: '命中原因', dataIndex: 'reasons', render: (values: string[]) => <Space size={[4, 4]} wrap>{values.length ? values.map(value => <Tag key={value}>{reasonLabel(value)}</Tag>) : <span className="muted">无命中</span>}</Space> },
      { title: '传输', dataIndex: 'transfer_status', width: 110, render: value => <span className={`transfer transfer-${value}`}>{transferLabels[value] ?? value}</span> },
    ]} />
    <Drawer width={520} title={selected ? `事件 #${selected.id}` : '事件详情'} open={!!selected} onClose={() => setSelected(null)} extra={selected && selected.action !== 'allow' && canOperate ? <Button onClick={() => feedback.mutate(selected.id)} loading={feedback.isPending}>标记误报</Button> : null}>
      {selected && <>
        <div className={`decision-hero decision-${selected.action}`}><span>内容判定</span><strong>{actionMeta[selected.action].label}</strong><small>传输状态：{transferLabels[selected.transfer_status] ?? selected.transfer_status}</small></div>
        <Descriptions column={1} bordered size="small" items={[
          { key: 'time', label: '发生时间', children: formatDateTime(selected.created_at) },
          { key: 'actor', label: '上传身份', children: selected.actor },
          { key: 'destination', label: '业务目标', children: selected.destination },
          { key: 'file', label: '文件', children: `${selected.filename} · ${formatBytes(selected.size)}` },
          { key: 'hash', label: 'SHA-256', children: <code className="hash">{selected.sha256 || '未计算'}</code> },
          { key: 'reasons', label: '原因', children: selected.reasons.map(reasonLabel).join('、') || '无命中' },
          { key: 'signals', label: '信号', children: selected.signals.join('、') || '无' },
          { key: 'model', label: '模型状态', children: selected.model_status || '未启用' },
          { key: 'upstream', label: '下游响应', children: selected.upstream_status ?? '—' },
        ]} />
      </>}
    </Drawer>
  </>
}
