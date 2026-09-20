import { Card, Select, Table, Tag, message } from 'antd'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { PageHeader } from '../components/PageHeader'
import { api } from '../lib/api'
import type { UserRisk } from '../lib/types'
import { operationsKeys, useUsers } from '../hooks/useOperations'

export function People({ canAdmin }: { canAdmin: boolean }) {
  const users = useUsers()
  const queryClient = useQueryClient()
  const update = useMutation({ mutationFn: (user: UserRisk) => api(`/v1/admin/users/${encodeURIComponent(user.actor)}`, { method: 'PUT', body: JSON.stringify({ status: user.status }) }), onSuccess: () => { message.success('人员风险状态已更新'); queryClient.invalidateQueries({ queryKey: operationsKeys.users }) }, onError: (error: Error) => message.error(error.message) })
  const meta = { normal: ['普通人员', 'default'], privileged: ['重点岗位', 'gold'], departing: ['离职流程中', 'red'] } as const
  return <><PageHeader eyebrow="Identity risk" title="人员风险" description="人员状态属于硬策略输入，模型和临时例外都不能绕过。" />
    <Card className="section-card"><Table<UserRisk> rowKey="actor" loading={users.isLoading} dataSource={users.data ?? []} pagination={false} columns={[
      { title: '业务身份', dataIndex: 'actor', render: value => <strong>{value}</strong> },
      { title: '当前风险层级', dataIndex: 'status', render: value => <Tag color={meta[value as keyof typeof meta][1]}>{meta[value as keyof typeof meta][0]}</Tag> },
      { title: '策略影响', dataIndex: 'status', render: value => value === 'departing' ? '所有上传进入阻断' : value === 'privileged' ? '外部上传进入人工复核' : '按内容和目标策略执行' },
      { title: '调整', width: 200, render: (_, user) => <Select value={user.status} disabled={!canAdmin} style={{ width: 160 }} onChange={status => update.mutate({ ...user, status })} options={[{ value: 'normal', label: '普通人员' }, { value: 'privileged', label: '重点岗位' }, { value: 'departing', label: '离职流程中' }]} /> },
    ]} /></Card></>
}

