/**
 * 管理员后台登录页面
 *
 * 专用于管理员登录，不对外开放
 */
import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Card, Form, Input, Button, message, Typography, Image } from 'antd'
import { UserOutlined, LockOutlined, SecurityScanOutlined, ReloadOutlined } from '@ant-design/icons'
import { authApi } from '../services/api'
import { useAuth } from '../contexts/AuthContext'

const { Title, Text } = Typography

export default function AdminLogin() {
  const [loading, setLoading] = useState(false)
  const [captchaEnabled, setCaptchaEnabled] = useState(false)
  const [captchaId, setCaptchaId] = useState('')
  const [captchaUrl, setCaptchaUrl] = useState('')
  const [refreshingCaptcha, setRefreshingCaptcha] = useState(false)
  const [form] = Form.useForm()
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuth()

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard'

  // 加载验证码配置
  useEffect(() => {
    loadCaptchaConfig()
  }, [])

  const loadCaptchaConfig = async () => {
    try {
      const config = await authApi.getCaptchaConfig()
      setCaptchaEnabled(config.enabled)
      if (config.enabled) {
        await refreshCaptcha()
      }
    } catch (err) {
      console.error('Failed to load captcha config:', err)
    }
  }

  const refreshCaptcha = async () => {
    setRefreshingCaptcha(true)
    try {
      const timestamp = Date.now()
      const url = `/api/v1/auth/captcha?t=${timestamp}`
      const response = await fetch(url)
      const captchaIdFromHeader = response.headers.get('X-Captcha-Id')
      if (captchaIdFromHeader) {
        setCaptchaId(captchaIdFromHeader)
        setCaptchaUrl(url)
      }
    } catch (err) {
      message.error('加载验证码失败')
    } finally {
      setRefreshingCaptcha(false)
    }
  }

  const handleLogin = async (values: { username: string; password: string; captcha_code?: string }) => {
    setLoading(true)
    try {
      const loginData: any = {
        username: values.username,
        password: values.password,
      }

      // 如果启用验证码，添加验证码参数
      if (captchaEnabled) {
        loginData.captcha_id = captchaId
        loginData.captcha_code = values.captcha_code
      }

      const res = await authApi.login(loginData)

      // 检查是否为管理员
      if (res.user.role !== 'admin') {
        message.error('此入口仅供管理员使用，请使用普通登录入口')
        return
      }

      login(res.access_token, res.user, res.refresh_token)
      message.success('登录成功')
      navigate(from, { replace: true })
    } catch (err: any) {
      const errorMsg = err.response?.data?.detail || err.message || '登录失败'
      message.error(typeof errorMsg === 'string' ? errorMsg : '登录失败')

      if (captchaEnabled) {
        await refreshCaptcha()
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #1e3c72 0%, #2a5298 100%)',
      }}
    >
      <Card
        style={{
          width: 450,
          boxShadow: '0 10px 40px rgba(0,0,0,0.3)',
          borderRadius: 12,
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <SecurityScanOutlined style={{ fontSize: 48, color: '#1e3c72', marginBottom: 16 }} />
          <Title level={2} style={{ marginBottom: 8 }}>
            管理员后台
          </Title>
          <Text type="secondary">AutoSpec 系统管理</Text>
        </div>

        <Form form={form} onFinish={handleLogin} layout="vertical">
          <Form.Item
            name="username"
            rules={[{ required: true, message: '请输入管理员账号' }]}
          >
            <Input
              prefix={<UserOutlined />}
              placeholder="管理员账号"
              size="large"
            />
          </Form.Item>

          <Form.Item
            name="password"
            rules={[{ required: true, message: '请输入密码' }]}
          >
            <Input.Password
              prefix={<LockOutlined />}
              placeholder="密码"
              size="large"
            />
          </Form.Item>

          {captchaEnabled && (
            <Form.Item
              name="captcha_code"
              rules={[{ required: true, message: '请输入验证码' }]}
            >
              <div style={{ display: 'flex', gap: 8 }}>
                <Input placeholder="验证码" size="large" />
                <div style={{ position: 'relative', width: 120 }}>
                  {captchaUrl && (
                    <Image
                      src={captchaUrl}
                      alt="验证码"
                      preview={false}
                      style={{ cursor: 'pointer', borderRadius: 4 }}
                      onClick={refreshCaptcha}
                    />
                  )}
                  <Button
                    icon={<ReloadOutlined spin={refreshingCaptcha} />}
                    onClick={refreshCaptcha}
                    loading={refreshingCaptcha}
                    style={{ position: 'absolute', right: 0, top: 0, opacity: 0.7 }}
                    size="small"
                  />
                </div>
              </div>
            </Form.Item>
          )}

          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              size="large"
              block
              loading={loading}
            >
              登录
            </Button>
          </Form.Item>
        </Form>

        <div style={{ textAlign: 'center', marginTop: 16 }}>
          <Text type="secondary" style={{ fontSize: 12 }}>
            ⚠️ 管理员专用入口，请勿分享
          </Text>
        </div>
      </Card>
    </div>
  )
}
