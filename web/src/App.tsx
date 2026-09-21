import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Alert, Avatar, Badge, Button, ConfigProvider, Dropdown, Layout, Menu, Spin, Typography, theme } from 'antd'
import type { MenuProps } from 'antd'
import {
  ApiOutlined, AuditOutlined, BarChartOutlined, BellOutlined, DashboardOutlined, ExperimentOutlined,
  FileProtectOutlined, LogoutOutlined, MenuFoldOutlined, MenuUnfoldOutlined, SafetyCertificateOutlined,
  SettingOutlined, TeamOutlined, UserOutlined,
} from '@ant-design/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { getHealth, getSession, setAdminToken, api } from './lib/api'
import type { Session } from './lib/types'
import { Login } from './pages/Login'

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

const navigation: MenuProps['items'] = [
  { type: 'group', label: '监测与响应', children: [
    { key: 'dashboard', icon: <DashboardOutlined />, label: '态势总览' },
    { key: 'incidents', icon: <BellOutlined />, label: '事件中心' },
    { key: 'audits', icon: <AuditOutlined />, label: '审计日志' },
  ] },
  { type: 'group', label: '策略与身份', children: [
    { key: 'policies', icon: <FileProtectOutlined />, label: '策略管理' },
    { key: 'exceptions', icon: <SafetyCertificateOutlined />, label: '例外与审批' },
    { key: 'people', icon: <TeamOutlined />, label: '人员风险' },
  ] },
  { type: 'group', label: '平台运营', children: [
    { key: 'integrations', icon: <ApiOutlined />, label: '集成与测试' },
    { key: 'reports', icon: <BarChartOutlined />, label: '运营报告' },
    { key: 'settings', icon: <SettingOutlined />, label: '系统设置' },
  ] },
]

const pageMeta: Record<string, { title: string; context: string }> = {
  dashboard: { title: '风险态势总览', context: 'Security posture' },
  incidents: { title: '事件中心', context: 'Investigation workspace' },
  audits: { title: '审计日志', context: 'Evidence ledger' },
  policies: { title: '策略管理', context: 'Policy control' },
  exceptions: { title: '例外与审批', context: 'Time-bound access' },
  people: { title: '人员风险', context: 'Identity risk' },
  integrations: { title: '集成与测试实验室', context: 'Business entry' },
  reports: { title: '运营报告', context: 'Risk analytics' },
  settings: { title: '系统设置', context: 'Trust configuration' },
}

export default function App() {
  const [page, setPage] = useState(() => location.hash.slice(1) || 'dashboard')
  const [collapsed, setCollapsed] = useState(() => window.innerWidth <= 900)
  const queryClient = useQueryClient()
  const health = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 30_000 })
  const sessionQuery = useQuery({ queryKey: ['session'], queryFn: getSession, retry: false })

  useEffect(() => {
    const listener = () => setPage(location.hash.slice(1) || 'dashboard')
    window.addEventListener('hashchange', listener)
    return () => window.removeEventListener('hashchange', listener)
  }, [])

  useEffect(() => {
    const compact = () => { if (window.innerWidth <= 900) setCollapsed(true) }
    window.addEventListener('resize', compact)
    return () => window.removeEventListener('resize', compact)
  }, [])

  const authenticate = async (_account: string, password: string) => {
    setAdminToken(password)
    const result = await queryClient.fetchQuery({ queryKey: ['session', Date.now()], queryFn: getSession })
    if (!result.authenticated) { setAdminToken(''); return false }
    queryClient.setQueryData(['session'], result)
    return true
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
  if (!session?.authenticated) return <Login session={session ?? { authenticated: false, mode: 'static' }} onStaticLogin={authenticate} />

  const displayName = session.identity?.name || session.identity?.email || session.identity?.subject || '管理员'
  const currentPage = pageMeta[page] ?? pageMeta.dashboard
  return <Layout className="app-shell">
    <Sider width={246} collapsedWidth={76} collapsed={collapsed} className="app-sider" trigger={null}>
      <div className="brand"><div className="brand-mark"><SafetyCertificateOutlined /></div>{!collapsed && <div><strong>Sentinel Gate</strong><span>DLP Operations</span></div>}</div>
      <Menu mode="inline" theme="dark" selectedKeys={[page]} items={navigation} onClick={({ key }) => go(key)} className="app-menu" />
      {!collapsed && <div className="sider-foot"><ExperimentOutlined /><span>Reference build · v{health.data?.version ?? '0.4'}</span></div>}
    </Sider>
    <Layout>
      <Header className="app-header">
        <Button className="header-toggle" type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? '展开导航' : '收起导航'} />
        <div className="header-context"><span>{currentPage.context}</span><strong>{currentPage.title}</strong></div>
        <div className="header-spacer" />
        <div className="header-environment"><span className="environment-dot" /><div><strong>本地演示环境</strong><small>仅处理合成数据</small></div></div>
        <div className="header-status"><Badge status={health.data?.status === 'ok' ? 'success' : 'error'} /><span>{health.data?.status === 'ok' ? '网关正常' : '网关异常'}</span></div>
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
