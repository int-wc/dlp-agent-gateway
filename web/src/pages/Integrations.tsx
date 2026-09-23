import { useState } from 'react'
import { Alert, Button, Card, Col, Descriptions, Form, Input, Radio, Row, Select, Space, Table, Tag, Upload, message } from 'antd'
import { ApiOutlined, InboxOutlined, SafetyOutlined } from '@ant-design/icons'
import { useQuery } from '@tanstack/react-query'
import { PageHeader } from '../components/PageHeader'
import { clientJSON, getFeishuAuditEvents, getFeishuSyncStatus, inspectFile, type DestinationInfo } from '../lib/api'
import type { FeishuAuditEvent } from '../lib/types'

export function Integrations() {
  const [token, setToken] = useState('')
  const [destinations, setDestinations] = useState<Record<string, DestinationInfo>>({})
  const [connected, setConnected] = useState(false)
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [form] = Form.useForm()
  const feishuStatus = useQuery({ queryKey: ['operations', 'feishu-status'], queryFn: getFeishuSyncStatus })
  const feishuEvents = useQuery({ queryKey: ['operations', 'feishu-events'], queryFn: getFeishuAuditEvents })
  const coverage = [
    { channel: 'HTTP / API 上传', status: 'protected', boundary: '通过网关检查后再转发', dependency: '真实系统授权、入口限流与回放保护' },
    { channel: 'PDF / DOCX / 图片', status: 'partial', boundary: '支持有界解析与可选 OCR', dependency: 'OCR 置信度、页码证据与异步大文件任务' },
    { channel: '浏览器 / 云盘', status: 'not_connected', boundary: '尚未接入', dependency: '受控浏览器、域名组、用户与设备范围' },
    { channel: '邮件 / 协作平台', status: 'not_connected', boundary: '尚未接入', dependency: '收件人、外部域和平台连接器' },
    { channel: '飞书行为审计', status: feishuStatus.data?.last_end ? 'partial' : 'not_connected', boundary: feishuStatus.data?.last_end ? '只读导出、下载与分享事件' : '尚未授权同步', dependency: '企业审计 API 权限与自建应用凭据；不能代替飞书 DLP 阻断' },
    { channel: 'USB / 打印 / 剪贴板 / RDP', status: 'not_connected', boundary: '尚未接入', dependency: '端点代理或 EDR / DLP 事件源' },
  ]
  const coverageMeta = {
    protected: { label: '已保护', color: 'green' },
    partial: { label: '部分覆盖', color: 'orange' },
    not_connected: { label: '未接入', color: 'default' },
  } as const

  const connect = async () => {
    try {
      setDestinations(await clientJSON<Record<string, DestinationInfo>>('/v1/destinations', token))
      setConnected(true); message.success('业务身份验证成功')
    } catch (error) { setConnected(false); message.error((error as Error).message) }
  }
  const submit = async (values: { destination: string; mode: 'check' | 'forward' }) => {
    if (!file) return message.warning('请选择合成测试文件')
    setLoading(true); setResult(null)
    try { setResult(await inspectFile(token, values.destination, values.mode, file)); message.success('检查完成') }
    catch (error) { message.error((error as Error).message) }
    finally { setLoading(false) }
  }
  return <>
    <PageHeader eyebrow="Business entry" title="集成与测试实验室" description="验证业务上传入口、目标白名单和检查后转发链路。只允许使用合成文件。" />
    <Alert type="warning" showIcon message="不要在公开演示环境上传真实业务文件" description="客户端凭据只保留在当前页面内存；刷新页面后自动清除。" />
    <Row gutter={[16, 16]} className="section-row">
      <Col xs={24} xl={9}><Card title={<Space><ApiOutlined />业务身份</Space>}>
        <Input.Password value={token} onChange={event => { setToken(event.target.value); setConnected(false) }} placeholder="客户端密钥；启用 mTLS 后可由业务证书替代" />
        <Button block type="primary" className="top-gap" onClick={connect} disabled={!token}>验证并读取目标</Button>
        <div className="connection-state">{connected ? <Tag color="green">已连接</Tag> : <Tag>未连接</Tag>}<span>网关不会将此密钥写入浏览器存储。</span></div>
      </Card></Col>
      <Col xs={24} xl={15}><Card title={<Space><InboxOutlined />合成文件检查</Space>}>
        <Form form={form} layout="vertical" initialValues={{ mode: 'check' }} onFinish={submit}>
          <Row gutter={12}><Col span={12}><Form.Item label="业务目标" name="destination" rules={[{ required: true }]}><Select disabled={!connected} placeholder="选择服务端允许的目标" options={Object.entries(destinations).map(([name, item]) => ({ value: name, label: `${name} · ${item.kind === 'external' ? '外部' : '内部'}` }))} /></Form.Item></Col><Col span={12}><Form.Item label="执行模式" name="mode"><Radio.Group optionType="button" buttonStyle="solid" options={[{ label: '仅检查', value: 'check' }, { label: '检查后转发', value: 'forward' }]} /></Form.Item></Col></Row>
          <Upload.Dragger maxCount={1} beforeUpload={selected => { setFile(selected); return false }} onRemove={() => { setFile(null); return true }}><p className="ant-upload-drag-icon"><SafetyOutlined /></p><p>拖入一份合成测试文件，或点击选择</p><p className="muted">最大 8 MiB；不支持或未完整解析的格式会失败关闭为人工复核</p></Upload.Dragger>
          <Button block type="primary" htmlType="submit" loading={loading} disabled={!connected || !file} className="top-gap">执行安全检查</Button>
        </Form>
      </Card></Col>
    </Row>
    {result && <Card title="执行结果" className="section-card"><Descriptions bordered column={{ xs: 1, sm: 2 }} items={Object.entries(result).map(([key, value]) => ({ key, label: key, children: typeof value === 'object' ? JSON.stringify(value) : String(value) }))} /></Card>}
    <Card title="已授权业务目标" className="section-card"><Row gutter={[12, 12]}>{Object.entries(destinations).map(([name, item]) => <Col xs={24} md={12} xl={8} key={name}><div className="integration-tile"><div><strong>{name}</strong><p>{item.kind === 'external' ? '外部业务系统' : '内部业务系统'}</p></div><Space direction="vertical" align="end"><Tag color={item.forwarding_configured ? 'green' : 'default'}>{item.forwarding_configured ? '可转发' : '仅检查'}</Tag><span className="muted">下游认证：{item.upstream_auth}</span></Space></div></Col>)}</Row>{connected && !Object.keys(destinations).length && <span className="muted">当前身份没有可用目标。</span>}</Card>
    <Card title="飞书行为审计" className="section-card" extra={<Tag color={feishuStatus.data?.last_end ? 'blue' : 'default'}>{feishuStatus.data?.last_end ? '只读同步' : '未接入'}</Tag>}>
      <p className="muted">接收飞书公开行为审计 API 中的导出、下载、分享和权限变更元数据。此通道提供事后观察，不检查文件内容，也不阻断飞书操作。</p>
      <Space wrap><span>最近同步：{feishuStatus.data?.updated_at ? new Date(feishuStatus.data.updated_at).toLocaleString() : '暂无'}</span><span>已导入：{feishuStatus.data?.imported_total ?? 0} 条</span></Space>
      <Table<FeishuAuditEvent> className="top-gap" size="small" rowKey="unique_id" loading={feishuEvents.isLoading}
        dataSource={feishuEvents.data ?? []} pagination={{ pageSize: 8 }} scroll={{ x: 700 }}
        locale={{ emptyText: '尚无飞书审计事件；需先获得企业授权并在远端配置只读同步。' }}
        columns={[
          { title: '时间', dataIndex: 'event_time', width: 175, render: value => new Date(value).toLocaleString() },
          { title: '事件', dataIndex: 'event_name', width: 210 },
          { title: '操作人 ID', dataIndex: 'operator_value', width: 170 },
          { title: '对象 ID', dataIndex: 'object_value' },
        ]} />
    </Card>
    <Card title="XDLP 覆盖边界" className="section-card coverage-card" extra={<span className="muted">明确已保护与未接入范围</span>}><Table rowKey="channel" size="small" pagination={false} dataSource={coverage} columns={[
      { title: '通道', dataIndex: 'channel', width: 220, render: value => <strong>{value}</strong> },
      { title: '状态', dataIndex: 'status', width: 120, render: value => { const meta = coverageMeta[value as keyof typeof coverageMeta]; return <Tag color={meta.color}>{meta.label}</Tag> } },
      { title: '当前边界', dataIndex: 'boundary', width: 260 },
      { title: '继续接入需要', dataIndex: 'dependency' },
    ]} /></Card>
  </>
}
