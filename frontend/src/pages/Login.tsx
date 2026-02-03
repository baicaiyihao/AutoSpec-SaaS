/**
 * 登录/注册页面
 */
import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Card, Form, Input, Button, Tabs, message, Typography, Image, Modal } from 'antd'
import { UserOutlined, LockOutlined, SecurityScanOutlined, ReloadOutlined } from '@ant-design/icons'
import { authApi, usersApi } from '../services/api'
import { useAuth } from '../contexts/AuthContext'

const { Title, Text } = Typography

export default function Login() {
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('login')
  const [captchaEnabled, setCaptchaEnabled] = useState(false)
  const [captchaId, setCaptchaId] = useState('')
  const [captchaUrl, setCaptchaUrl] = useState('')
  const [refreshingCaptcha, setRefreshingCaptcha] = useState(false)
  const [changePwdModalOpen, setChangePwdModalOpen] = useState(false)
  const [changePwdLoading, setChangePwdLoading] = useState(false)
  const [changePwdForm] = Form.useForm()
  const [pendingLoginData, setPendingLoginData] = useState<{token: string, user: any, refreshToken?: string} | null>(null)
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

      // 🔥 检查是否需要强制修改密码
      if (res.password_must_change) {
        // 保存登录信息但不跳转，先要求修改密码
        setPendingLoginData({ token: res.access_token, user: res.user, refreshToken: res.refresh_token })
        message.warning('首次登录需要修改密码，请设置新密码')
        setChangePwdModalOpen(true)
      } else {
        // 正常登录流程
        login(res.access_token, res.user, res.refresh_token)
        message.success(`欢迎回来, ${res.user.username}`)
        navigate(from, { replace: true })
      }
    } catch (err: any) {
      message.error(err.response?.data?.detail || '登录失败')
      // 验证码错误时刷新验证码
      if (captchaEnabled && err.response?.status === 400) {
        await refreshCaptcha()
      }
    } finally {
      setLoading(false)
    }
  }

  const handleRegister = async (values: { username: string; password: string; confirm: string }) => {
    if (values.password !== values.confirm) {
      message.error('两次密码不一致')
      return
    }
    setLoading(true)
    try {
      const res = await authApi.register({ username: values.username, password: values.password })
      if (res.pending) {
        message.success('注册成功，请等待管理员审核后登录')
        setActiveTab('login')
      } else {
        login(res.access_token, res.user, res.refresh_token)
        message.success('注册成功')
        navigate(from, { replace: true })
      }
    } catch (err: any) {
      message.error(err.response?.data?.detail || '注册失败')
    } finally {
      setLoading(false)
    }
  }

  const handleForceChangePassword = async (values: { old_password: string; new_password: string; confirm: string }) => {
    if (values.new_password !== values.confirm) {
      message.error('两次新密码不一致')
      return
    }
    if (!pendingLoginData) return

    setChangePwdLoading(true)
    try {
      // 临时登录以调用修改密码 API
      const tempToken = pendingLoginData.token
      localStorage.setItem('autospec_token', tempToken)

      await usersApi.changePassword({
        old_password: values.old_password,
        new_password: values.new_password,
      })

      message.success('密码修改成功，欢迎使用！')
      setChangePwdModalOpen(false)
      changePwdForm.resetFields()

      // 正式登录
      login(pendingLoginData.token, pendingLoginData.user, pendingLoginData.refreshToken)
      navigate(from, { replace: true })
    } catch (err: any) {
      message.error(err.response?.data?.detail || '修改密码失败')
    } finally {
      setChangePwdLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <Card className="w-[400px] shadow-lg">
        <div className="text-center mb-6">
          <SecurityScanOutlined className="text-4xl text-blue-500" />
          <Title level={3} className="!mt-2 !mb-1">AutoSpec</Title>
          <Text type="secondary">智能合约 AI 自动化审计平台</Text>
        </div>

        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          centered
          items={[
            {
              key: 'login',
              label: '登录',
              children: (
                <Form onFinish={handleLogin} autoComplete="off" size="large">
                  <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
                    <Input prefix={<UserOutlined />} placeholder="用户名" />
                  </Form.Item>
                  <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
                    <Input.Password prefix={<LockOutlined />} placeholder="密码" />
                  </Form.Item>
                  {captchaEnabled && (
                    <Form.Item>
                      <div className="flex gap-2">
                        <Form.Item
                          name="captcha_code"
                          rules={[{ required: true, message: '请输入验证码' }]}
                          className="flex-1 !mb-0"
                        >
                          <Input placeholder="验证码" maxLength={4} />
                        </Form.Item>
                        <div
                          className="relative cursor-pointer hover:opacity-80"
                          onClick={refreshCaptcha}
                          title="点击刷新验证码"
                        >
                          {captchaUrl && (
                            <img
                              src={captchaUrl}
                              alt="验证码"
                              className="h-10 w-32 border border-gray-300 rounded"
                            />
                          )}
                          {refreshingCaptcha && (
                            <div className="absolute inset-0 flex items-center justify-center bg-white bg-opacity-70">
                              <ReloadOutlined spin />
                            </div>
                          )}
                        </div>
                      </div>
                    </Form.Item>
                  )}
                  <Form.Item>
                    <Button type="primary" htmlType="submit" loading={loading} block>
                      登录
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'register',
              label: '注册',
              children: (
                <Form onFinish={handleRegister} autoComplete="off" size="large">
                  <Form.Item
                    name="username"
                    rules={[
                      { required: true, message: '请输入用户名' },
                      { min: 2, message: '用户名至少2个字符' },
                    ]}
                  >
                    <Input prefix={<UserOutlined />} placeholder="用户名" />
                  </Form.Item>
                  <Form.Item
                    name="password"
                    rules={[
                      { required: true, message: '请输入密码' },
                      { min: 8, message: '密码至少8位' },
                      {
                        pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/,
                        message: '密码需包含大小写字母和数字',
                      },
                    ]}
                    extra="密码需包含大小写字母和数字，长度至少8位"
                  >
                    <Input.Password prefix={<LockOutlined />} placeholder="密码" />
                  </Form.Item>
                  <Form.Item
                    name="confirm"
                    rules={[{ required: true, message: '请确认密码' }]}
                  >
                    <Input.Password prefix={<LockOutlined />} placeholder="确认密码" />
                  </Form.Item>
                  <Form.Item>
                    <Button type="primary" htmlType="submit" loading={loading} block>
                      注册
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
          ]}
        />
      </Card>

      {/* 强制修改密码对话框 */}
      <Modal
        title="首次登录 - 修改密码"
        open={changePwdModalOpen}
        onCancel={() => {
          setChangePwdModalOpen(false)
          setPendingLoginData(null)
          changePwdForm.resetFields()
        }}
        footer={null}
        maskClosable={false}
        closable={false}
      >
        <div className="mb-4">
          <Text type="secondary">
            为了账户安全，首次登录需要修改默认密码。请输入当前密码和新密码。
          </Text>
        </div>
        <Form form={changePwdForm} onFinish={handleForceChangePassword} layout="vertical">
          <Form.Item
            name="old_password"
            label="当前密码"
            rules={[{ required: true, message: '请输入当前密码' }]}
          >
            <Input.Password placeholder="输入当前密码" />
          </Form.Item>
          <Form.Item
            name="new_password"
            label="新密码"
            rules={[
              { required: true, message: '请输入新密码' },
              { min: 8, message: '密码至少8位' },
              {
                pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/,
                message: '密码需包含大小写字母和数字',
              },
            ]}
            extra="密码需包含大小写字母和数字，长度至少8位"
          >
            <Input.Password placeholder="输入新密码" />
          </Form.Item>
          <Form.Item
            name="confirm"
            label="确认新密码"
            rules={[{ required: true, message: '请确认新密码' }]}
          >
            <Input.Password placeholder="再次输入新密码" />
          </Form.Item>
          <Form.Item className="!mb-0">
            <Button type="primary" htmlType="submit" loading={changePwdLoading} block>
              确认修改
            </Button>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
