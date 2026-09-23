import { useState } from 'react'
import { Alert, Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography, message } from 'antd'
import { HistoryOutlined, PlusOutlined } from '@ant-design/icons'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PageHeader } from '../components/PageHeader'
import { api, getPolicyVersions, previewPolicy, rollbackPolicy } from '../lib/api'
import type { Policy, PolicyPreview, PolicyRevision } from '../lib/types'
import { operationsKeys, usePolicies } from '../hooks/useOperations'

const modes = [
  { value: 'draft', label: '草稿', hint: '不参与检测' },
  { value: 'monitor', label: '监控', hint: '记录命中，不改变判定' },
  { value: 'enforce', label: '强制', hint: '按配置执行复核或阻断' },
] as const

const effectLabel: Record<string, string> = {
  none: '无策略效果', monitor: '只记录命中', review: '要求复核', block: '阻断',
}

export function Policies({ canAdmin }: { canAdmin: boolean }) {
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm()
  const [historyPolicy, setHistoryPolicy] = useState<Policy | null>(null)
  const [candidate, setCandidate] = useState<Policy | null>(null)
  const [rollbackTarget, setRollbackTarget] = useState<number | null>(null)
  const [sample, setSample] = useState('')
  const [destinationKind, setDestinationKind] = useState<'internal' | 'external'>('external')
  const [previewResult, setPreviewResult] = useState<PolicyPreview | null>(null)
  const policies = usePolicies()
  const queryClient = useQueryClient()
  const history = useQuery({
    queryKey: ['operations', 'policy-versions', historyPolicy?.id],
    queryFn: () => getPolicyVersions(historyPolicy!.id),
    enabled: historyPolicy !== null,
  })
  const refresh = () => queryClient.invalidateQueries({ queryKey: operationsKeys.policies })
  const create = useMutation({
    mutationFn: (value: Omit<Policy, 'id' | 'enabled' | 'version'>) =>
      api<Policy>('/v1/admin/policies', { method: 'POST', body: JSON.stringify(value) }),
    onSuccess: () => { message.success('策略已创建'); setOpen(false); form.resetFields(); refresh() },
    onError: (error: Error) => message.error(error.message),
  })
  const update = useMutation({
    mutationFn: (item: Policy) => api<Policy>(`/v1/admin/policies/${item.id}`, {
      method: 'PUT', body: JSON.stringify(item),
    }),
    onSuccess: () => { message.success('策略已更新'); setCandidate(null); setPreviewResult(null); refresh() },
    onError: (error: Error) => { message.error(error.message); refresh() },
  })
  const preview = useMutation({
    mutationFn: () => previewPolicy(candidate!, sample, destinationKind),
    onSuccess: setPreviewResult,
    onError: (error: Error) => message.error(error.message),
  })
  const rollback = useMutation({
    mutationFn: (target: { policyId: number; targetVersion: number; expectedVersion: number }) =>
      rollbackPolicy(target.policyId, target.targetVersion, target.expectedVersion),
    onSuccess: (item: Policy) => {
      message.success(`已恢复为新版本 v${item.version}`)
      setHistoryPolicy(item)
      setCandidate(null)
      setPreviewResult(null)
      setRollbackTarget(null)
      refresh()
      queryClient.invalidateQueries({ queryKey: ['operations', 'policy-versions', item.id] })
    },
    onError: (error: Error) => { message.error(error.message); refresh() },
  })

  const changeMode = (item: Policy, mode: Policy['mode']) => {
    const next = { ...item, mode }
    if (mode === 'enforce') {
      setCandidate(next)
      setRollbackTarget(null)
      setSample('')
      setDestinationKind('external')
      setPreviewResult(null)
    } else {
      update.mutate(next)
    }
  }

  const restoreRevision = (item: PolicyRevision) => {
    if (!historyPolicy) return
    if (item.mode === 'enforce') {
      setCandidate({ ...historyPolicy, keyword: item.keyword, action: item.action, scope: item.scope, mode: item.mode })
      setRollbackTarget(item.version)
      setSample('')
      setPreviewResult(null)
      setDestinationKind('external')
      setHistoryPolicy(null)
      return
    }
    Modal.confirm({
      title: `恢复到 v${item.version}？`,
      content: `将创建一个新版本，并恢复关键词“${item.keyword}”及其 ${item.mode} 模式。`,
      okText: '确认恢复',
      onOk: () => rollback.mutateAsync({
        policyId: item.policy_id, targetVersion: item.version, expectedVersion: historyPolicy.version,
      }).then(() => undefined),
    })
  }

  return <>
    <PageHeader title="策略管理" description="先观察命中，再验证强制效果；每次修改保留可回退的版本。"
      extra={<Button type="primary" icon={<PlusOutlined />} disabled={!canAdmin} onClick={() => setOpen(true)}>新建策略</Button>} />
    <Card className="section-card">
      <Table<Policy> rowKey="id" loading={policies.isLoading} dataSource={policies.data ?? []}
        pagination={false} scroll={{ x: 750 }} columns={[
          { title: '策略', dataIndex: 'id', width: 95, render: (_, item) => <span className="muted">#{item.id} · v{item.version}</span> },
          { title: '敏感关键词', dataIndex: 'keyword', render: value => <strong>{value}</strong> },
          { title: '执行动作', dataIndex: 'action', render: value => <Tag color={value === 'block' ? 'red' : 'orange'}>{value === 'block' ? '阻断' : '人工复核'}</Tag> },
          { title: '适用范围', dataIndex: 'scope', render: value => ({ all: '全部目标', internal: '内部目标', external: '外部目标' }[value as string] ?? value) },
          { title: '模式', dataIndex: 'mode', width: 160, render: (mode, item) =>
            <Select aria-label={`策略 ${item.id} 模式`} value={mode} disabled={!canAdmin || update.isPending}
              onChange={value => changeMode(item, value)} style={{ width: 130 }}
              options={modes.map(option => ({ value: option.value, label: option.label }))} /> },
          { title: '版本', width: 90, render: (_, item) =>
            <Button type="link" size="small" icon={<HistoryOutlined />} onClick={() => setHistoryPolicy(item)}>历史</Button> },
        ]} />
    </Card>

    <Modal title="新建字面关键词策略" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnHidden>
      <Form form={form} layout="vertical" initialValues={{ action: 'review', scope: 'external', mode: 'draft' }}
        onFinish={value => create.mutate(value)}>
        <Form.Item label="敏感关键词" name="keyword" rules={[{ required: true, min: 2, max: 64 }]}>
          <Input placeholder="例如：虚构项目代号" />
        </Form.Item>
        <Space align="start" style={{ width: '100%' }}>
          <Form.Item label="命中动作" name="action" rules={[{ required: true }]}>
            <Select style={{ width: 180 }} options={[{ value: 'review', label: '人工复核' }, { value: 'block', label: '直接阻断' }]} />
          </Form.Item>
          <Form.Item label="适用范围" name="scope" rules={[{ required: true }]}>
            <Select style={{ width: 180 }} options={[{ value: 'external', label: '仅外部目标' }, { value: 'internal', label: '仅内部目标' }, { value: 'all', label: '全部目标' }]} />
          </Form.Item>
        </Space>
        <Form.Item label="初始模式" name="mode" rules={[{ required: true }]} extra="建议先监控命中情况，再切换为强制执行。">
          <Select options={modes.filter(option => option.value !== 'enforce').map(option => ({ value: option.value, label: `${option.label} · ${option.hint}` }))} />
        </Form.Item>
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          监控模式只记录命中信号；内置硬规则始终生效。
        </Typography.Paragraph>
        <Button block type="primary" htmlType="submit" loading={create.isPending}>创建策略</Button>
      </Form>
    </Modal>

    <Modal title={rollbackTarget === null ? '切换为强制执行' : `恢复强制策略 v${rollbackTarget}`}
      open={candidate !== null}
      onCancel={() => { setCandidate(null); setPreviewResult(null); setRollbackTarget(null) }}
      onOk={() => {
        if (!candidate) return
        if (rollbackTarget !== null) {
          rollback.mutate({ policyId: candidate.id, targetVersion: rollbackTarget, expectedVersion: candidate.version })
        } else {
          update.mutate(candidate)
        }
      }} okText="确认启用强制"
      okButtonProps={{ disabled: !previewResult?.proposed.matched, loading: update.isPending || rollback.isPending }}>
      <Alert type="info" showIcon style={{ marginBottom: 16 }}
        message="仅预览这条字面关键词策略对合成文本的效果；真实上传仍会叠加解析、硬规则和身份判断。" />
      <Space direction="vertical" style={{ width: '100%' }}>
        <Select value={destinationKind} onChange={value => { setDestinationKind(value); setPreviewResult(null) }}
          options={[{ value: 'external', label: '外部目标' }, { value: 'internal', label: '内部目标' }]} />
        <Input.TextArea aria-label="合成测试文本" value={sample}
          onChange={event => { setSample(event.target.value); setPreviewResult(null) }}
          placeholder="输入不含真实敏感信息的合成测试文本" maxLength={4096} rows={4} showCount />
        <Button onClick={() => preview.mutate()} loading={preview.isPending} disabled={!sample.trim()}>预览效果</Button>
        {previewResult && <Alert type="success" showIcon
          message={`当前：${effectLabel[previewResult.current?.effect ?? 'none']} → 切换后：${effectLabel[previewResult.proposed.effect]}`}
          description={previewResult.proposed.matched ? '测试文本命中了此策略。' : '测试文本未命中；请换用包含该关键词的合成样本确认效果。'} />}
      </Space>
    </Modal>

    <Modal title={`策略 #${historyPolicy?.id ?? ''} · 版本历史`} open={historyPolicy !== null}
      onCancel={() => setHistoryPolicy(null)} footer={null} width={760}>
      <Table<PolicyRevision> size="small" rowKey="version" loading={history.isLoading}
        dataSource={history.data ?? []} pagination={{ pageSize: 8 }} scroll={{ x: 650 }} columns={[
          { title: '版本', dataIndex: 'version', width: 75, render: value => `v${value}` },
          { title: '时间', dataIndex: 'changed_at', width: 165, render: value => new Date(value).toLocaleString() },
          { title: '操作人', dataIndex: 'changed_by', width: 130 },
          { title: '配置', render: (_, item) => `${item.mode} · ${item.action} · ${item.scope}` },
          { title: '操作', width: 90, render: (_, item) => item.version === historyPolicy?.version
            ? <span className="muted">当前</span>
            : <Button type="link" size="small" disabled={!canAdmin || rollback.isPending}
                onClick={() => restoreRevision(item)}>恢复</Button> },
        ]} />
      <Typography.Text type="secondary">恢复操作会创建新版本，原历史不会删除。</Typography.Text>
    </Modal>
  </>
}
