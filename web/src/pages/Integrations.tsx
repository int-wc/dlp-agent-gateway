import { useState } from 'react'
import { Alert, Button, Card, Col, Descriptions, Form, Input, Radio, Row, Select, Space, Tag, Upload, message } from 'antd'
import { ApiOutlined, InboxOutlined, SafetyOutlined } from '@ant-design/icons'
import { PageHeader } from '../components/PageHeader'
import { clientJSON, inspectFile, type DestinationInfo } from '../lib/api'

export function Integrations() {
  const [token, setToken] = useState('')
  const [destinations, setDestinations] = useState<Record<string, DestinationInfo>>({})
  const [connected, setConnected] = useState(false)
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [form] = Form.useForm()

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
  </>
}

