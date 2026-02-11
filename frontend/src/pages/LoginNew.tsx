/**
 * C端登录页面 - 高端极简设计
 * 参考 Linear、Stripe、Vercel 的设计风格
 */
import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Card, Typography, App, Spin } from 'antd'
import { SecurityScanOutlined } from '@ant-design/icons'
import { useCurrentAccount, useSignPersonalMessage, ConnectButton } from '@mysten/dapp-kit'
import { authApi } from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import './LoginNew.css'

const { Title, Text } = Typography

export default function LoginNew() {
  const [loading, setLoading] = useState(false)
  const [hasAttempted, setHasAttempted] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuth()
  const currentAccount = useCurrentAccount()
  const { mutate: signMessage } = useSignPersonalMessage()
  const { message } = App.useApp()

  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard'

  // 钱包连接后自动触发登录流程（仅一次）
  useEffect(() => {
    if (currentAccount && !loading && !hasAttempted) {
      handleWalletLogin()
    }
  }, [currentAccount])

  const handleWalletLogin = async () => {
    if (!currentAccount) {
      message.error('请先连接钱包')
      return
    }

    if (hasAttempted) {
      return
    }

    setHasAttempted(true)
    setLoading(true)
    try {
      const challengeRes = await authApi.getWalletChallenge(currentAccount.address)
      const challenge = challengeRes.message

      const publicKeyBytes = Array.from(currentAccount.publicKey).slice(1)
      const publicKeyHex = publicKeyBytes
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      signMessage(
        {
          message: new TextEncoder().encode(challenge),
        },
        {
          onSuccess: async (result) => {
            try {
              const signatureBytes = Uint8Array.from(atob(result.signature), c => c.charCodeAt(0))
              const pureSignature = signatureBytes.slice(1, 65)
              const signatureHex = Array.from(pureSignature)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('')

              const response = await authApi.verifyWalletLogin({
                wallet_address: currentAccount.address,
                signature: signatureHex,
                message: challenge,
                public_key: publicKeyHex,
              })

              login(response.access_token, response.user, response.refresh_token)
              message.success('登录成功！')
              navigate(from, { replace: true })
            } catch (error: any) {
              console.error('验证签名失败:', error)
              message.error(`登录失败: ${error.response?.data?.detail || error.message}`)
              setLoading(false)
              setHasAttempted(false)
            }
          },
          onError: (error) => {
            console.error('签名失败:', error)
            message.error('签名失败')
            setLoading(false)
          },
        }
      )
    } catch (error: any) {
      console.error('钱包登录失败:', error)
      message.error(`登录失败: ${error.response?.data?.detail || error.message}`)
      setLoading(false)
      setHasAttempted(false)
    }
  }

  return (
    <div className="login-premium">
      {/* Animated Background Grid */}
      <div className="grid-background">
        <div className="grid-line horizontal" style={{ top: '20%' }}></div>
        <div className="grid-line horizontal" style={{ top: '40%' }}></div>
        <div className="grid-line horizontal" style={{ top: '60%' }}></div>
        <div className="grid-line horizontal" style={{ top: '80%' }}></div>
        <div className="grid-line vertical" style={{ left: '20%' }}></div>
        <div className="grid-line vertical" style={{ left: '40%' }}></div>
        <div className="grid-line vertical" style={{ left: '60%' }}></div>
        <div className="grid-line vertical" style={{ left: '80%' }}></div>
      </div>

      {/* Gradient Orbs */}
      <div className="gradient-orb orb-1"></div>
      <div className="gradient-orb orb-2"></div>
      <div className="gradient-orb orb-3"></div>

      {/* Main Content */}
      <div className="login-content-premium">
        {/* Logo Badge */}
        <div className="logo-badge">
          <SecurityScanOutlined className="logo-icon-premium" />
        </div>

        {/* Title */}
        <Title level={1} className="login-title-premium">
          AutoSpec
        </Title>
        <Text className="login-tagline">AI-Powered Smart Contract Security</Text>

        {/* Login Card */}
        <Card className="login-card-premium">
          {loading ? (
            <div className="loading-state">
              <Spin size="large" />
              <Text className="loading-text">正在连接...</Text>
            </div>
          ) : (
            <>
              <div className="connect-prompt">
                <Text className="connect-title">使用 Sui 钱包登录</Text>
                <Text className="connect-subtitle">连接钱包以开始智能合约安全审计</Text>
              </div>
              <div className="connect-button-premium">
                <ConnectButton
                  connectText="连接钱包"
                  className="wallet-connect-btn"
                />
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  )
}
