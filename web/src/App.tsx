import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Alert, Avatar, Badge, Button, ConfigProvider, Dropdown, Input, Layout, Menu, Space, Spin, Typography, message, theme } from 'antd'
import {
  ApiOutlined, AuditOutlined, BarChartOutlined, BellOutlined, DashboardOutlined, ExperimentOutlined,
  FileProtectOutlined, LogoutOutlined, MenuFoldOutlined, MenuUnfoldOutlined, SafetyCertificateOutlined,
  SettingOutlined, TeamOutlined, UserOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getHealth, getSession, setAdminToken, api } from './lib/api'
import type { Session } from './lib/types'

const Overview = lazy(() => import('./pages/Overview').then(module => ({ default: module.Overview })))
const Incidents = lazy(() => import('./pages/Incidents').then(module => ({ default: module.Incidents })))
const AuditLogs = lazy(() => import('./pages/AuditLogs').then(module => ({ default: module.AuditLogs })))
const Policies = lazy(() => import('./pages/Policies').then(module => ({ default: module.Policies })))
const Exceptions = lazy(() => import('./pages/Exceptions').then(module => ({ default: module.Exceptions })))
const People = lazy(() => import('./pages/People').then(module => ({ default: module.People })))
const Integrations = lazy(() => import('./pages/Integrations').then(module => ({ default: module.Integrations })))
const Reports = lazy(() => import('./pages/Reports').then(module => ({ default: module.Reports })))
const Settings = lazy(() => import('./pages/Settings').then(module => ({ default: module.Settings })))

const { Header, Sider, Content } = Layout

const navigation = [
  { key: 'dashboard', icon: <DashboardOutlined />, label: '态势总览' },
  { key: 'incidents', icon: <BellOutlined />, label: '事件中心' },
  { key: 'audits', icon: <AuditOutlined />, label: '审计日志' },
  { type: 'divider' as const },
  { key: 'policies', icon: <FileProtectOutlined />, label: '策略管理' },
  { key: 'exceptions', icon: <SafetyCertificateOutlined />, label: '例外与审批' },
  { key: 'people', icon: <TeamOutlined />, label: '人员风险' },
  { type: 'divider' as const },
  { key: 'integrations', icon: <ApiOutlined />, label: '集成与测试' },
  { key: 'reports', icon: <BarChartOutlined />, label: '运营报告' },
  { key: 'settings', icon: <SettingOutlined />, label: '系统设置' },
]

function Login({ session, onAuthenticated }: { session: Session; onAuthenticated: () => Promise<void> }) {
  const [token, setToken] = useState('')
  const [loading, setLoading] = useState(false)
  const supportsOIDC = session.mode === 'oidc' || session.mode === 'oidc_or_static'
  const supportsStatic = session.mode === 'static' || session.mode === 'oidc_or_static'
  const submit = async () => {
    setLoading(true); setAdminToken(token)
    try { await onAuthenticated() } finally { setLoading(false) }
  }
  return <div className="login-shell">
    <div className="login-visual">
      <div className="brand-mark large"><SafetyCertificateOutlined /></div>
      <div className="login-copy"><span>Sentinel Gate</span><h1>让每一次业务上传<br />都有可解释的安全决策。</h1><p>策略执行、身份风险、人工复核和审计证据集中在一个运营工作台。</p></div>
      <div className="visual-grid" />
    </div>
    <div className="login-panel">
      <div className="login-card">
        <div className="eyebrow">DLP operations console</div><h2>进入运营台</h2><p>使用企业身份或本地演示管理员密钥。</p>
        {supportsOIDC && <Button type="primary" size="large" block icon={<UserOutlined />} href="/auth/login">使用企业账号登录</Button>}
        {supportsOIDC && supportsStatic && <div className="login-divider"><span>或使用本地演示身份</span></div>}
        {supportsStatic && <Space.Compact block size="large"><Input.Password value={token} onChange={event => setToken(event.target.value)} onPressEnter={submit} placeholder="管理员密钥" /><Button type="primary" loading={loading} onClick={submit} disabled={!token}>连接</Button></Space.Compact>}
        <Alert className="login-alert" type="info" showIcon message="参考实现" description="请只使用合成数据。生产接入前仍需完成组织级部署与安全评审。" />
      </div>
    </div>
  </div>
}

export default function App() {
  const [page, setPage] = useState(() => location.hash.slice(1) || 'dashboard')
  const [collapsed, setCollapsed] = useState(false)
  const queryClient = useQueryClient()
  const health = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 30_000 })
  const sessionQuery = useQuery({ queryKey: ['session'], queryFn: getSession, retry: false })

  useEffect(() => {
    const listener = () => setPage(location.hash.slice(1) || 'dashboard')
    window.addEventListener('hashchange', listener)
    return () => window.removeEventListener('hashchange', listener)
  }, [])

  const authenticate = async () => {
    const result = await queryClient.fetchQuery({ queryKey: ['session', Date.now()], queryFn: getSession })
    if (!result.authenticated) { setAdminToken(''); message.error('管理员身份验证失败'); return }
    queryClient.setQueryData(['session'], result)
  }
  const logout = async () => {
    try { await api('/auth/logout', { method: 'POST' }) } catch { /* local token mode */ }
    setAdminToken(''); queryClient.clear(); location.hash = 'dashboard'; location.reload()
  }
  const go = (key: string) => { location.hash = key; setPage(key) }
  const session = sessionQuery.data
  const role = session?.identity?.role
  const canOperate = role === 'admin' || role === 'operator'
  const canAdmin = role === 'admin'
  const body = useMemo(() => ({
    dashboard: <Overview />, incidents: <Incidents canOperate={canOperate} />, audits: <AuditLogs canOperate={canOperate} />,
    policies: <Policies canAdmin={canAdmin} />, exceptions: <Exceptions canOperate={canOperate} />, people: <People canAdmin={canAdmin} />,
    integrations: <Integrations />, reports: <Reports />, settings: <Settings health={health.data} session={session!} />,
  }[page] ?? <Overview />), [page, canOperate, canAdmin, health.data, session])

  if (sessionQuery.isLoading) return <div className="boot"><Spin size="large" /><span>正在建立安全会话…</span></div>
  if (sessionQuery.isError) return <div className="boot"><Alert type="error" showIcon message="无法连接网关" description={(sessionQuery.error as Error).message} /></div>
  if (!session?.authenticated) return <Login session={session ?? { authenticated: false, mode: 'static' }} onAuthenticated={authenticate} />

  const displayName = session.identity?.name || session.identity?.email || session.identity?.subject || '管理员'
  return <Layout className="app-shell">
    <Sider width={246} collapsedWidth={76} collapsed={collapsed} className="app-sider" trigger={null}>
      <div className="brand"><div className="brand-mark"><SafetyCertificateOutlined /></div>{!collapsed && <div><strong>Sentinel Gate</strong><span>DLP Operations</span></div>}</div>
      <Menu mode="inline" theme="dark" selectedKeys={[page]} items={navigation} onClick={({ key }) => go(key)} className="app-menu" />
      {!collapsed && <div className="sider-foot"><ExperimentOutlined /><span>Reference build · v{health.data?.version ?? '0.3'}</span></div>}
    </Sider>
    <Layout>
      <Header className="app-header">
        <Button type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed(value => !value)} />
        <div className="header-spacer" />
        <Badge status={health.data?.status === 'ok' ? 'success' : 'error'} text={health.data?.status === 'ok' ? '网关正常' : '网关异常'} />
        <Dropdown menu={{ items: [{ key: 'logout', icon: <LogoutOutlined />, label: '退出登录', onClick: logout }] }} placement="bottomRight">
          <Button type="text" className="user-button"><Avatar size="small" icon={<UserOutlined />} /><span>{displayName}</span><Typography.Text type="secondary">{role}</Typography.Text></Button>
        </Dropdown>
      </Header>
      <Content className="app-content"><Suspense fallback={<div className="page-loading"><Spin size="large" /></div>}>{body}</Suspense></Content>
    </Layout>
  </Layout>
}

export function ThemedApp() {
  return <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm, token: { colorPrimary: '#2869d8', colorInfo: '#2869d8', borderRadius: 10, colorBgLayout: '#f3f6fa', fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' }, components: { Layout: { headerBg: '#fff', siderBg: '#111c2e' }, Menu: { darkItemBg: '#111c2e', darkItemSelectedBg: '#213a62', darkItemHoverBg: '#182942' }, Card: { headerFontSize: 15 } } }}><App /></ConfigProvider>
}
