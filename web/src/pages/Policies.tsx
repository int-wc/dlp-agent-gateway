import { useState } from 'react'
import { Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography, message } from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { PageHeader } from '../components/PageHeader'
import { api } from '../lib/api'
import type { Policy } from '../lib/types'
import { operationsKeys, usePolicies } from '../hooks/useOperations'

export function Policies({ canAdmin }: { canAdmin: boolean }) {
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm()
  const policies = usePolicies()
  const queryClient = useQueryClient()
  const refresh = () => queryClient.invalidateQueries({ queryKey: operationsKeys.policies })
  const create = useMutation({ mutationFn: (value: Omit<Policy, 'id' | 'enabled'>) => api('/v1/admin/policies', { method: 'POST', body: JSON.stringify(value) }), onSuccess: () => { message.success('策略已创建'); setOpen(false); form.resetFields(); refresh() }, onError: (error: Error) => message.error(error.message) })
  const update = useMutation({ mutationFn: (policy: Policy) => api(`/v1/admin/policies/${policy.id}`, { method: 'PUT', body: JSON.stringify(policy) }), onSuccess: () => { message.success('策略状态已更新'); refresh() }, onError: (error: Error) => message.error(error.message) })
  const modes = [
    { value: 'draft', label: '草稿', hint: '不参与检测' },
    { value: 'monitor', label: '监控', hint: '记录命中，不改变判定' },
    { value: 'enforce', label: '强制', hint: '按配置执行复核或阻断' },
  ] as const
  return <>
    <PageHeader title="策略管理" description="策略先以草稿或监控方式验证，再由管理员切换为强制执行。" extra={<Button type="primary" icon={<PlusOutlined />} disabled={!canAdmin} onClick={() => setOpen(true)}>新建策略</Button>} />
    <Card className="section-card"><Table<Policy> rowKey="id" loading={policies.isLoading} dataSource={policies.data ?? []} pagination={false} columns={[
      { title: 'ID', dataIndex: 'id', width: 80, render: value => <span className="muted">#{value}</span> },
      { title: '敏感关键词', dataIndex: 'keyword', render: value => <strong>{value}</strong> },
      { title: '执行动作', dataIndex: 'action', render: value => <Tag color={value === 'block' ? 'red' : 'orange'}>{value === 'block' ? '阻断' : '人工复核'}</Tag> },
      { title: '适用范围', dataIndex: 'scope', render: value => ({ all: '全部目标', internal: '内部目标', external: '外部目标' }[value as string] ?? value) },
      { title: '模式', dataIndex: 'mode', width: 190, render: (mode, item) => <Select aria-label={`策略 ${item.id} 模式`} value={mode} disabled={!canAdmin || update.isPending} onChange={value => update.mutate({ ...item, mode: value })} style={{ width: 150 }} options={modes.map(option => ({ value: option.value, label: option.label }))} /> },
    ]} /></Card>
    <Modal title="新建字面关键词策略" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnHidden>
      <Form form={form} layout="vertical" initialValues={{ action: 'review', scope: 'external', mode: 'draft' }} onFinish={value => create.mutate(value)}>
        <Form.Item label="敏感关键词" name="keyword" rules={[{ required: true, min: 2, max: 64 }]}><Input placeholder="例如：项目代号（请只使用合成词）" /></Form.Item>
        <Space align="start" style={{ width: '100%' }}><Form.Item label="命中动作" name="action" rules={[{ required: true }]}><Select style={{ width: 180 }} options={[{ value: 'review', label: '人工复核' }, { value: 'block', label: '直接阻断' }]} /></Form.Item><Form.Item label="适用范围" name="scope" rules={[{ required: true }]}><Select style={{ width: 180 }} options={[{ value: 'external', label: '仅外部目标' }, { value: 'internal', label: '仅内部目标' }, { value: 'all', label: '全部目标' }]} /></Form.Item></Space>
        <Form.Item label="初始模式" name="mode" rules={[{ required: true }]} extra="建议先监控命中情况，再切换为强制执行。"><Select options={modes.map(option => ({ value: option.value, label: `${option.label} · ${option.hint}` }))} /></Form.Item>
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>监控模式只记录 <code>policy_monitor_ID</code> 信号，不会降低或提高文件判定；内置秘密和人员硬规则仍然生效。</Typography.Paragraph>
        <Button block type="primary" htmlType="submit" loading={create.isPending}>创建策略</Button>
      </Form>
    </Modal>
  </>
}
