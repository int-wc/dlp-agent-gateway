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
import { BrandMark } from './components/BrandMark'

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

const pageContext: Record<string, { section: string; title: string }> = {
  dashboard: { section: '监测与响应', title: '态势总览' },
  incidents: { section: '监测与响应', title: '事件中心' },
  audits: { section: '监测与响应', title: '审计日志' },
  policies: { section: '策略与身份', title: '策略管理' },
  exceptions: { section: '策略与身份', title: '例外与审批' },
  people: { section: '策略与身份', title: '人员风险' },
  integrations: { section: '平台运营', title: '集成与测试' },
  reports: { section: '平台运营', title: '运营报告' },
  settings: { section: '平台运营', title: '系统设置' },
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
  const currentPage = pageContext[page] ?? pageContext.dashboard
  return <Layout className="app-shell">
    <Sider width={246} collapsedWidth={76} collapsed={collapsed} className="app-sider" trigger={null}>
      <div className="brand"><BrandMark />{!collapsed && <div><strong>Sentinel Gate</strong><span>DLP Operations</span></div>}</div>
      <Menu mode="inline" theme="dark" selectedKeys={[page]} items={navigation} onClick={({ key }) => go(key)} className="app-menu" />
      {!collapsed && <div className="sider-foot"><ExperimentOutlined /><span>Reference build · v{health.data?.version ?? '0.4'}</span></div>}
    </Sider>
    <Layout>
      <Header className="app-header">
        <Button className="header-toggle" type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? '展开导航' : '收起导航'} />
        <div className="header-context"><span>{currentPage.section}</span><strong>{currentPage.title}</strong></div>
        <div className="header-spacer" />
        <div className="header-environment"><Badge status={health.data?.status === 'ok' ? 'success' : 'error'} /><div><strong>本地演示</strong><small>{health.data?.status === 'ok' ? `运行正常 · v${health.data?.version ?? '—'}` : '网关异常'}</small></div></div>
        <Dropdown menu={{ items: [{ key: 'logout', icon: <LogoutOutlined />, label: '退出登录', onClick: logout }] }} placement="bottomRight">
          <Button type="text" className="user-button"><Avatar size="small" icon={<UserOutlined />} /><span>{displayName}</span><Typography.Text type="secondary">{role}</Typography.Text></Button>
        </Dropdown>
      </Header>
      <Content className="app-content"><Suspense fallback={<div className="page-loading"><Spin size="large" /></div>}>{body}</Suspense></Content>
    </Layout>
  </Layout>
}

export function ThemedApp() {
  return <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm, token: { colorPrimary: '#2f6fd2', colorInfo: '#2f6fd2', colorSuccess: '#238763', colorWarning: '#b77924', colorError: '#c84d52', borderRadius: 7, controlHeight: 36, fontSize: 13, colorBgLayout: '#f4f6f9', colorBorder: '#dfe4ea', fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif', boxShadow: 'none', boxShadowSecondary: 'none' }, components: { Layout: { headerBg: '#fff', siderBg: '#111827' }, Menu: { darkItemBg: '#111827', darkItemSelectedBg: '#243652', darkItemHoverBg: '#1b293d', itemBorderRadius: 6 }, Card: { headerFontSize: 14 }, Table: { headerBg: '#f7f8fa', headerColor: '#667085', rowHoverBg: '#f7f9fc' } } }}><App /></ConfigProvider>
}
