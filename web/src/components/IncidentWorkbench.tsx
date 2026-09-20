import { useEffect, useMemo, useState } from 'react'
import {
  Avatar, Button, Checkbox, Descriptions, Empty, Form, Input, Modal, Popover, Progress, Radio,
  Select, Space, Table, Tabs, Tag, Timeline, Tooltip, Typography, message,
} from 'antd'
import type { TableColumnsType } from 'antd'
import {
  CheckCircleOutlined, ClockCircleOutlined, ColumnHeightOutlined, FileSearchOutlined,
  SafetyCertificateOutlined, SearchOutlined, StopOutlined, UserOutlined,
} from '@ant-design/icons'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Action, Audit, ExceptionRequest, Feedback } from '../lib/types'
import { operationsKeys } from '../hooks/useOperations'
import { actionMeta, formatBytes, formatDateTime, reasonLabel, transferLabels } from './AuditTable'

type Workflow = 'all' | 'open' | 'resolved'
type ColumnKey = 'risk' | 'time' | 'identity' | 'file' | 'reason' | 'transfer' | 'status'

const defaultColumns: ColumnKey[] = ['risk', 'time', 'identity', 'file', 'reason', 'transfer', 'status']
const columnOptions = [
  { label: '风险', value: 'risk' }, { label: '时间', value: 'time' }, { label: '身份与目标', value: 'identity' },
  { label: '文件', value: 'file' }, { label: '命中原因', value: 'reason' }, { label: '传输', value: 'transfer' }, { label: '处置状态', value: 'status' },
]

function riskScore(audit: Audit) {
  let score = audit.action === 'block' ? 88 : 62
  if (audit.reasons.some(reason => ['private_key', 'aws_access_key', 'departing_user'].includes(reason))) score += 9
  if (audit.transfer_status === 'failed' || audit.transfer_status === 'not_configured') score += 3
  return Math.min(score, 99)
}

function riskLevel(score: number) {
  if (score >= 85) return { label: '高危', color: 'red', className: 'risk-high' }
  if (score >= 65) return { label: '中危', color: 'orange', className: 'risk-medium' }
  return { label: '关注', color: 'gold', className: 'risk-low' }
}

function verdictMeta(feedback?: Feedback) {
  if (!feedback) return { label: '待处置', color: 'orange', className: 'open' }
  return feedback.verdict === 'false_positive'
    ? { label: '已关闭 · 误报', color: 'default', className: 'resolved' }
    : { label: '已确认风险', color: 'red', className: 'confirmed' }
}

export function IncidentWorkbench({ audits, feedback, exceptions, loading, canOperate }: {
  audits: Audit[]
  feedback: Feedback[]
  exceptions: ExceptionRequest[]
  loading: boolean
  canOperate: boolean
}) {
  const [search, setSearch] = useState('')
  const [decision, setDecision] = useState<Action | 'all'>('all')
  const [workflow, setWorkflow] = useState<Workflow>('all')
  const [windowSize, setWindowSize] = useState<'all' | '24h' | '7d'>('all')
  const [visibleColumns, setVisibleColumns] = useState<ColumnKey[]>(defaultColumns)
  const [selectedID, setSelectedID] = useState<number | null>(null)
  const [feedbackOpen, setFeedbackOpen] = useState(false)
  const [form] = Form.useForm<{ verdict: Feedback['verdict']; note: string }>()
  const queryClient = useQueryClient()
  const feedbackMap = useMemo(() => new Map(feedback.map(item => [item.audit_id, item])), [feedback])

  const data = useMemo(() => {
    const cutoff = windowSize === '24h' ? Date.now() - 24 * 60 * 60 * 1000 : windowSize === '7d' ? Date.now() - 7 * 24 * 60 * 60 * 1000 : 0
    const needle = search.trim().toLowerCase()
    return audits.filter(item => {
      if (item.action === 'allow') return false
      if (decision !== 'all' && item.action !== decision) return false
      const resolved = feedbackMap.has(item.id)
      if (workflow === 'open' && resolved) return false
      if (workflow === 'resolved' && !resolved) return false
      if (cutoff && new Date(item.created_at).getTime() < cutoff) return false
      return !needle || [item.id, item.actor, item.destination, item.filename, ...item.reasons, ...item.signals].join(' ').toLowerCase().includes(needle)
    })
  }, [audits, decision, feedbackMap, search, windowSize, workflow])

  useEffect(() => {
    if (!data.length) { setSelectedID(null); return }
    if (!selectedID || !data.some(item => item.id === selectedID)) setSelectedID(data[0].id)
  }, [data, selectedID])

  const selected = data.find(item => item.id === selectedID) ?? null
  const selectedFeedback = selected ? feedbackMap.get(selected.id) : undefined
  const selectedException = selected ? exceptions.find(item => item.audit_id === selected.id) : undefined
  const actorActivity = selected ? audits.filter(item => item.actor === selected.actor).slice(0, 8) : []

  const submitFeedback = useMutation({
    mutationFn: (value: { verdict: Feedback['verdict']; note: string }) => api(`/v1/admin/audits/${selected?.id}/feedback`, { method: 'PUT', body: JSON.stringify(value) }),
    onSuccess: () => {
      message.success('处置结论已写入审计记录')
      setFeedbackOpen(false)
      queryClient.invalidateQueries({ queryKey: operationsKeys.all })
    },
    onError: (error: Error) => message.error(error.message),
  })

  const openFeedback = (verdict: Feedback['verdict']) => {
    form.setFieldsValue({ verdict, note: selectedFeedback?.note ?? '' })
    setFeedbackOpen(true)
  }

  const allColumns: TableColumnsType<Audit> = [
    { key: 'risk', title: '风险', width: 92, render: (_, item) => { const score = riskScore(item); const meta = riskLevel(score); return <div className={`risk-score ${meta.className}`}><strong>{score}</strong><span>{meta.label}</span></div> } },
    { key: 'time', title: '检测时间', dataIndex: 'created_at', width: 146, render: value => <div className="table-date"><strong>{formatDateTime(value, 'time')}</strong><span>{formatDateTime(value, 'date')}</span></div> },
    { key: 'identity', title: '身份与目标', width: 172, render: (_, item) => <div className="identity-cell"><Avatar size={28} icon={<UserOutlined />} /><div><strong>{item.actor}</strong><span>→ {item.destination}</span></div></div> },
    { key: 'file', title: '文件', dataIndex: 'filename', ellipsis: true, width: 190, render: (value, item) => <div><strong className="file-name">{value}</strong><div className="cell-sub">{formatBytes(item.size)}</div></div> },
    { key: 'reason', title: '命中原因', dataIndex: 'reasons', width: 190, render: (values: string[]) => <Space size={[4, 4]} wrap>{values.slice(0, 2).map(value => <Tag key={value} className="signal-tag">{reasonLabel(value)}</Tag>)}{values.length > 2 && <Tag>+{values.length - 2}</Tag>}</Space> },
    { key: 'transfer', title: '传输', dataIndex: 'transfer_status', width: 106, render: value => <span className={`transfer transfer-${value}`}>{transferLabels[value] ?? value}</span> },
    { key: 'status', title: '处置状态', width: 122, render: (_, item) => { const meta = verdictMeta(feedbackMap.get(item.id)); return <Tag color={meta.color}>{meta.label}</Tag> } },
  ]
  const columns = allColumns.filter(column => visibleColumns.includes(column.key as ColumnKey))

  const timeline = selected ? [
    { color: '#2b6edb', dot: <FileSearchOutlined />, children: <div className="timeline-entry"><strong>网关完成内容检测</strong><span>{formatDateTime(selected.created_at)} · 判定为{actionMeta[selected.action].label}</span></div> },
    selected.transfer_status !== 'not_requested' ? { color: selected.forwarded ? '#18a174' : '#d95a57', children: <div className="timeline-entry"><strong>传输控制：{transferLabels[selected.transfer_status] ?? selected.transfer_status}</strong><span>{selected.upstream_status ? `下游响应 HTTP ${selected.upstream_status}` : '未向下游释放文件'}</span></div> } : null,
    selectedException ? { color: selectedException.status === 'approved' ? '#18a174' : '#d89a31', children: <div className="timeline-entry"><strong>例外申请：{({ pending: '待审批', approved: '已批准', rejected: '已拒绝' } as const)[selectedException.status]}</strong><span>{formatDateTime(selectedException.created_at)} · {selectedException.justification}</span></div> } : null,
    selectedFeedback ? { color: selectedFeedback.verdict === 'false_positive' ? '#8792a5' : '#d95a57', dot: <CheckCircleOutlined />, children: <div className="timeline-entry"><strong>{selectedFeedback.verdict === 'false_positive' ? '运营人员标记为误报' : '运营人员确认风险'}</strong><span>{formatDateTime(selectedFeedback.created_at)}{selectedFeedback.note ? ` · ${selectedFeedback.note}` : ''}</span></div> } : null,
  ].filter(Boolean) as { color: string; dot?: React.ReactNode; children: React.ReactNode }[] : []

  const detailTabs = selected ? [
    { key: 'overview', label: '概览', children: <div className="incident-tab-content">
      <div className="detail-summary-grid">
        <div><span>业务身份</span><strong>{selected.actor}</strong><small>上传至 {selected.destination}</small></div>
        <div><span>文件对象</span><strong title={selected.filename}>{selected.filename}</strong><small>{formatBytes(selected.size)}</small></div>
        <div><span>内容判定</span><strong>{actionMeta[selected.action].label}</strong><small>{selected.reasons.length} 个命中条件</small></div>
        <div><span>处置结论</span><strong>{verdictMeta(selectedFeedback).label}</strong><small>{selectedFeedback ? formatDateTime(selectedFeedback.created_at) : '等待运营人员复核'}</small></div>
      </div>
      <div className="detail-section"><div className="detail-section-title">命中条件</div><Space size={[6, 8]} wrap>{selected.reasons.length ? selected.reasons.map(reason => <Tag color="red" key={reason}>{reasonLabel(reason)}</Tag>) : <Typography.Text type="secondary">没有命中条件</Typography.Text>}</Space></div>
      {selectedFeedback?.note && <div className="operator-note"><span>处置备注</span><p>{selectedFeedback.note}</p></div>}
      {selectedException && <div className="operator-note exception-note"><span>例外申请 #{selectedException.id}</span><p>{selectedException.justification}</p></div>}
    </div> },
    { key: 'events', label: `事件 ${timeline.length}`, children: <div className="incident-tab-content timeline-wrap"><Timeline items={timeline} /></div> },
    { key: 'activity', label: `用户活动 ${actorActivity.length}`, children: <div className="incident-tab-content"><Table<Audit> rowKey="id" size="small" pagination={false} dataSource={actorActivity} columns={[
      { title: '时间', dataIndex: 'created_at', width: 150, render: value => formatDateTime(value) },
      { title: '文件', dataIndex: 'filename', ellipsis: true },
      { title: '判定', dataIndex: 'action', width: 90, render: (value: Action) => <Tag color={actionMeta[value].color}>{actionMeta[value].label}</Tag> },
    ]} /></div> },
    { key: 'evidence', label: '证据', children: <div className="incident-tab-content">
      <Descriptions size="small" column={1} className="evidence-descriptions" items={[
        { key: 'hash', label: 'SHA-256', children: <code className="hash">{selected.sha256 || '未计算'}</code> },
        { key: 'signals', label: '检测信号', children: selected.signals.length ? selected.signals.join('、') : '无附加信号' },
        { key: 'model', label: '模型状态', children: selected.model_status || '未启用' },
        { key: 'transfer', label: '传输结果', children: transferLabels[selected.transfer_status] ?? selected.transfer_status },
        { key: 'upstream', label: '下游响应', children: selected.upstream_status ? `HTTP ${selected.upstream_status}` : '—' },
      ]} />
      <div className="evidence-boundary"><SafetyCertificateOutlined /><div><strong>证据边界</strong><p>当前记录保存文件摘要、检测信号与处置轨迹，不在运营台回显原始文件内容。</p></div></div>
    </div> },
  ] : []

  return <>
    <div className="incident-toolbar">
      <Input allowClear prefix={<SearchOutlined />} placeholder="搜索事件、身份、文件、目标或命中原因" value={search} onChange={event => setSearch(event.target.value)} />
      <Select value={decision} onChange={setDecision} options={[{ value: 'all', label: '全部判定' }, { value: 'review', label: '待复核' }, { value: 'block', label: '已阻断' }]} />
      <Select value={workflow} onChange={setWorkflow} options={[{ value: 'all', label: '全部状态' }, { value: 'open', label: '待处置' }, { value: 'resolved', label: '已处置' }]} />
      <Select value={windowSize} onChange={setWindowSize} options={[{ value: 'all', label: '全部时间' }, { value: '24h', label: '近 24 小时' }, { value: '7d', label: '近 7 天' }]} />
      <Popover trigger="click" placement="bottomRight" content={<div className="column-picker"><strong>显示列</strong><Checkbox.Group value={visibleColumns} options={columnOptions} onChange={values => setVisibleColumns(values as ColumnKey[])} /></div>}><Button icon={<ColumnHeightOutlined />}>列设置</Button></Popover>
    </div>
    <div className="incident-workbench">
      <div className="incident-list-pane">
        <div className="incident-list-meta"><span><strong>{data.length}</strong> 个事件</span><span>{data.filter(item => !feedbackMap.has(item.id)).length} 个待处置</span></div>
        <Table<Audit> rowKey="id" size="small" loading={loading} dataSource={data} columns={columns} pagination={{ pageSize: 12, showSizeChanger: false, hideOnSinglePage: true }} scroll={{ x: 920 }} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前筛选条件下没有事件" /> }} rowClassName={record => record.id === selectedID ? 'selected-incident-row' : ''} onRow={record => ({ onClick: () => setSelectedID(record.id) })} />
      </div>
      <aside className="incident-detail-pane">
        {!selected ? <div className="detail-empty"><FileSearchOutlined /><strong>选择一个事件开始调查</strong><span>这里会展示证据链、相关活动与处置操作。</span></div> : <>
          <div className="incident-detail-head">
            <div className="incident-title-row"><div><span className="incident-kicker">INC-{String(selected.id).padStart(5, '0')}</span><h2>{selected.filename}</h2></div><Progress type="circle" percent={riskScore(selected)} size={58} strokeColor={riskScore(selected) >= 85 ? '#d95555' : '#dc9733'} format={value => <span className="risk-ring-value">{value}</span>} /></div>
            <Space size={[6, 6]} wrap><Tag color={actionMeta[selected.action].color}>{actionMeta[selected.action].label}</Tag><Tag color={verdictMeta(selectedFeedback).color}>{verdictMeta(selectedFeedback).label}</Tag><span className="detail-time"><ClockCircleOutlined /> {formatDateTime(selected.created_at)}</span></Space>
          </div>
          <Tabs className="incident-tabs" items={detailTabs} />
          <div className="incident-action-bar">
            <div><span>运营处置</span><small>{canOperate ? '结论会写入审计记录并进入策略优化统计' : '当前角色只有查看权限'}</small></div>
            <Space>
              <Tooltip title={canOperate ? '' : '需要 operator 或 admin 角色'}><Button disabled={!canOperate} onClick={() => openFeedback('false_positive')}>标记误报</Button></Tooltip>
              <Tooltip title={canOperate ? '' : '需要 operator 或 admin 角色'}><Button type="primary" danger icon={<StopOutlined />} disabled={!canOperate} onClick={() => openFeedback('true_positive')}>确认风险</Button></Tooltip>
            </Space>
          </div>
        </>}
      </aside>
    </div>
    <Modal title={selected ? `处置事件 INC-${String(selected.id).padStart(5, '0')}` : '处置事件'} open={feedbackOpen} onCancel={() => setFeedbackOpen(false)} footer={null} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={value => submitFeedback.mutate(value)} initialValues={{ verdict: 'true_positive', note: '' }}>
        <Form.Item label="处置结论" name="verdict" rules={[{ required: true }]}><Radio.Group optionType="button" buttonStyle="solid" options={[{ value: 'true_positive', label: '确认风险' }, { value: 'false_positive', label: '标记误报' }]} /></Form.Item>
        <Form.Item label="处置备注" name="note" rules={[{ max: 240 }]}><Input.TextArea rows={4} maxLength={240} showCount placeholder="记录判断依据、与业务方的确认结果或后续建议" /></Form.Item>
        <Button block type="primary" htmlType="submit" loading={submitFeedback.isPending}>保存处置结论</Button>
      </Form>
    </Modal>
  </>
}
