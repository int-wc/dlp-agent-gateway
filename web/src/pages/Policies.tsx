import { useState } from 'react'
import { Button, Card, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, message } from 'antd'
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
  return <>
    <PageHeader eyebrow="Policy control" title="策略管理" description="策略修改必须由管理员完成；模型建议不会自动改变执行结果。" extra={<Button type="primary" icon={<PlusOutlined />} disabled={!canAdmin} onClick={() => setOpen(true)}>新建策略</Button>} />
    <Card className="section-card"><Table<Policy> rowKey="id" loading={policies.isLoading} dataSource={policies.data ?? []} pagination={false} columns={[
      { title: 'ID', dataIndex: 'id', width: 80, render: value => <span className="muted">#{value}</span> },
      { title: '敏感关键词', dataIndex: 'keyword', render: value => <strong>{value}</strong> },
      { title: '执行动作', dataIndex: 'action', render: value => <Tag color={value === 'block' ? 'red' : 'orange'}>{value === 'block' ? '阻断' : '人工复核'}</Tag> },
      { title: '适用范围', dataIndex: 'scope', render: value => ({ all: '全部目标', internal: '内部目标', external: '外部目标' }[value as string] ?? value) },
      { title: '状态', dataIndex: 'enabled', width: 120, render: (enabled, item) => <Popconfirm title={enabled ? '确认停用这条策略？' : '确认启用这条策略？'} onConfirm={() => update.mutate({ ...item, enabled: !enabled })}><Switch checked={enabled} disabled={!canAdmin} /></Popconfirm> },
    ]} /></Card>
    <Modal title="新建字面关键词策略" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnHidden>
      <Form form={form} layout="vertical" initialValues={{ action: 'review', scope: 'external' }} onFinish={value => create.mutate(value)}>
        <Form.Item label="敏感关键词" name="keyword" rules={[{ required: true, min: 2, max: 64 }]}><Input placeholder="例如：项目代号（请只使用合成词）" /></Form.Item>
        <Space align="start" style={{ width: '100%' }}><Form.Item label="命中动作" name="action" rules={[{ required: true }]}><Select style={{ width: 180 }} options={[{ value: 'review', label: '人工复核' }, { value: 'block', label: '直接阻断' }]} /></Form.Item><Form.Item label="适用范围" name="scope" rules={[{ required: true }]}><Select style={{ width: 180 }} options={[{ value: 'external', label: '仅外部目标' }, { value: 'internal', label: '仅内部目标' }, { value: 'all', label: '全部目标' }]} /></Form.Item></Space>
        <Button block type="primary" htmlType="submit" loading={create.isPending}>创建策略</Button>
      </Form>
    </Modal>
  </>
}

