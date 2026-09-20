import { Card, Col, Descriptions, Empty, Row, Table, Tag } from 'antd'
import { PageHeader } from '../components/PageHeader'
import type { Health, Session } from '../lib/types'
import { useEvents } from '../hooks/useOperations'

export function Settings({ health, session }: { health?: Health; session: Session }) {
  const events = useEvents()
  return <>
    <PageHeader eyebrow="Trust configuration" title="系统设置" description="确认当前实例的存储、身份认证、解析能力和管理员操作轨迹。" />
    <Row gutter={[16, 16]}>
      <Col xs={24} xl={12}><Card title="运行能力"><Descriptions column={1} items={[
        { key: 'version', label: '网关版本', children: health?.version ?? '读取中' },
        { key: 'storage', label: '审计存储', children: <Tag color={health?.storage === 'postgresql' ? 'green' : 'orange'}>{health?.storage ?? '未知'}</Tag> },
        { key: 'analyzer', label: '复杂文档解析', children: health?.analyzer_enabled ? '已启用' : '仅文本规则模式' },
        { key: 'model', label: '本地模型建议', children: health?.model_enabled ? '已启用' : '未启用' },
        { key: 'oidc', label: 'OIDC', children: health?.oidc_enabled ? '已配置' : '未配置' },
        { key: 'mtls', label: '业务入口 mTLS', children: health?.mtls_required ? '强制要求' : '可选 / Bearer 兼容' },
      ]} /></Card></Col>
      <Col xs={24} xl={12}><Card title="当前会话"><Descriptions column={1} items={[
        { key: 'subject', label: '身份', children: session.identity?.name || session.identity?.email || session.identity?.subject || '未识别' },
        { key: 'role', label: '角色', children: <Tag color="blue">{session.identity?.role ?? '—'}</Tag> },
        { key: 'mode', label: '认证方式', children: session.mode },
        { key: 'boundary', label: '安全边界', children: '本实例仍是参考实现；仅处理主动接入网关的流量。' },
      ]} /></Card></Col>
    </Row>
    <Card title="管理员操作事件" className="section-card"><Table rowKey={record => String(record.id)} loading={events.isLoading} dataSource={events.data ?? []} pagination={{ pageSize: 10 }} locale={{ emptyText: <Empty description="暂无管理员操作事件" /> }} columns={[{ title: '时间', dataIndex: 'created_at', render: value => new Date(String(value)).toLocaleString('zh-CN', { hour12: false }) }, { title: '事件', dataIndex: 'event' }, { title: '目标', dataIndex: 'target' }]} /></Card>
  </>
}

