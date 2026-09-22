import { useState } from 'react'
import { Alert, Button, Checkbox, Divider, Form, Input } from 'antd'
import {
  ArrowRightOutlined, AuditOutlined, CheckCircleFilled, CloudServerOutlined,
  LockOutlined, SafetyCertificateOutlined, SafetyOutlined, UserOutlined,
} from '@ant-design/icons'
import type { Session } from '../lib/types'
import { BrandMark } from '../components/BrandMark'

type LoginValues = {
  account: string
  password: string
  remember: boolean
}

const rememberedAccountKey = 'dlp-console-remembered-account'

function rememberedAccount() {
  try { return localStorage.getItem(rememberedAccountKey) || 'local-admin' } catch { return 'local-admin' }
}

export function Login({ session, onStaticLogin }: {
  session: Session
  onStaticLogin: (account: string, password: string) => Promise<boolean>
}) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const supportsOIDC = session.mode === 'oidc' || session.mode === 'oidc_or_static'
  const supportsStatic = session.mode === 'static' || session.mode === 'oidc_or_static'

  const submit = async (values: LoginValues) => {
    setLoading(true)
    setError('')
    setNotice('')
    try {
      const authenticated = await onStaticLogin(values.account.trim(), values.password)
      if (!authenticated) {
        setError('账号或密码不正确，请检查后重试。')
        return
      }
      try {
        if (values.remember) localStorage.setItem(rememberedAccountKey, values.account.trim())
        else localStorage.removeItem(rememberedAccountKey)
      } catch { /* browser storage is optional */ }
    } catch {
      setError('暂时无法连接身份服务，请稍后重试。')
    } finally {
      setLoading(false)
    }
  }

  return <main className="login-shell">
    <section className="login-visual" aria-label="Sentinel Gate product introduction">
      <div className="visual-grid" />
      <div className="visual-glow visual-glow-one" />
      <div className="visual-glow visual-glow-two" />
      <div className="login-brand">
        <BrandMark large />
        <div><strong>Sentinel Gate</strong><span>DLP Operations Platform</span></div>
      </div>
      <div className="login-copy">
        <span>Enterprise data protection</span>
        <h1>让每一次数据流转，<br />都经过可信决策。</h1>
        <p>连接业务上传入口，在文件离开可信边界前完成内容识别、策略执行、人工复核与审计留痕。</p>
        <div className="login-capabilities">
          <div><SafetyOutlined /><span><strong>上传前检测</strong><small>敏感数据实时判定</small></span></div>
          <div><AuditOutlined /><span><strong>全程可追溯</strong><small>决策与处置独立留痕</small></span></div>
          <div><CloudServerOutlined /><span><strong>数据不出域</strong><small>本地解析与模型建议</small></span></div>
        </div>
      </div>
      <div className="login-visual-footer"><CheckCircleFilled /> Fail closed · Check before forward</div>
    </section>

    <section className="login-panel">
      <div className="login-card">
        <div className="login-mobile-brand"><BrandMark /><strong>Sentinel Gate</strong></div>
        <div className="login-kicker">安全运营控制台</div>
        <h2>欢迎回来</h2>
        <p className="login-subtitle">登录后查看风险事件、策略执行与审计证据。</p>

        {supportsStatic && <Form<LoginValues> layout="vertical" requiredMark={false} initialValues={{ account: rememberedAccount(), remember: true }} onFinish={submit} className="login-form">
          <Form.Item label="账号" name="account" rules={[{ required: true, message: '请输入账号' }]}>
            <Input size="large" prefix={<UserOutlined />} placeholder="工作邮箱或账号" autoComplete="username" autoFocus />
          </Form.Item>
          <Form.Item label="密码" name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password size="large" prefix={<LockOutlined />} placeholder="请输入密码" autoComplete="current-password" />
          </Form.Item>
          <div className="login-options">
            <Form.Item name="remember" valuePropName="checked" noStyle><Checkbox>记住账号</Checkbox></Form.Item>
            <Button type="link" onClick={() => { setError(''); setNotice('密码找回将在接入实际身份系统后开放，请联系系统管理员。') }}>忘记密码？</Button>
          </div>
          {error && <Alert type="error" showIcon message={error} className="login-feedback" />}
          {notice && <Alert type="info" showIcon message={notice} closable onClose={() => setNotice('')} className="login-feedback" />}
          <Button type="primary" size="large" block htmlType="submit" loading={loading} className="login-submit">登录运营台 <ArrowRightOutlined /></Button>
        </Form>}

        {supportsOIDC && supportsStatic && <Divider plain>或</Divider>}
        {supportsOIDC && <Button size="large" block icon={<SafetyCertificateOutlined />} href="/auth/login" className="sso-button">使用企业身份中心登录</Button>}

        <div className="login-environment">
          <span><span className="environment-dot" />{supportsOIDC ? '企业身份登录已配置' : '本地演示认证'}</span>
          <small>{supportsOIDC ? '账号由组织身份提供方验证' : '账号体系将在确认实际登录方式后接入'}</small>
        </div>
        <div className="login-security-note"><LockOutlined /> 请仅使用合成数据；不要在演示环境处理真实敏感文件。</div>
      </div>
      <footer className="login-footer"><span>© 2026 Sentinel Gate</span><span>Privacy · Security · Auditability</span></footer>
    </section>
  </main>
}
