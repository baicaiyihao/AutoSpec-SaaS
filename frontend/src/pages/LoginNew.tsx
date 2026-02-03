/**
 * C端登录页面 - 纯钱包登录
 *
 * 用户通过连接 Sui 钱包并签名来登录
 */
import { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Card, Typography, Space, App, Spin } from 'antd'
import { WalletOutlined } from '@ant-design/icons'
import { useCurrentAccount, useSignPersonalMessage, ConnectButton } from '@mysten/dapp-kit'
import { authApi } from '../services/api'
import { useAuth } from '../contexts/AuthContext'

const { Title, Text, Paragraph } = Typography

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

  // 🔥 钱包连接后自动触发登录流程（仅一次）
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
      return  // 防止重复触发
    }

    setHasAttempted(true)
    setLoading(true)
    try {
      // 1. 获取签名挑战
      const challengeRes = await authApi.getWalletChallenge(currentAccount.address)
      const challenge = challengeRes.message

      // 2. 提取 Ed25519 public key（去掉 Sui 的 scheme byte）
      const publicKeyBytes = Array.from(currentAccount.publicKey).slice(1)
      const publicKeyHex = publicKeyBytes
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')

      // 3. 签名挑战
      signMessage(
        {
          message: new TextEncoder().encode(challenge),
        },
        {
          onSuccess: async (result) => {
            try {
              // 4. 提取纯签名（Sui 签名格式：1 byte scheme + 64 bytes 签名 + 32 bytes 公钥）
              const signatureBytes = Uint8Array.from(atob(result.signature), c => c.charCodeAt(0))
              const pureSignature = signatureBytes.slice(1, 65)  // 跳过 scheme，取 64 bytes 签名
              const signatureHex = Array.from(pureSignature)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join('')

              // 5. 验证签名并登录
              const response = await authApi.verifyWalletLogin({
                wallet_address: currentAccount.address,
                signature: signatureHex,
                message: challenge,
                public_key: publicKeyHex,
              })

              // 5. 保存登录状态
              login(response.access_token, response.user, response.refresh_token)
              message.success('登录成功！')
              navigate(from, { replace: true })
            } catch (error: any) {
              console.error('🔴 验证签名失败:', error)
              message.error(`登录失败: ${error.response?.data?.detail || error.message}`)
              setLoading(false)
              setHasAttempted(false)  // 允许重试
            }
          },
          onError: (error) => {
            console.error('🔴 签名失败:', error)
            message.error('签名失败')
            setLoading(false)
            // 不重置 hasAttempted，防止重复弹出
          },
        }
      )
    } catch (error: any) {
      console.error('🔴 钱包登录失败:', error)
      message.error(`登录失败: ${error.response?.data?.detail || error.message}`)
      setLoading(false)
      setHasAttempted(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        padding: '24px',
      }}
    >
      <Card
        style={{
          width: '100%',
          maxWidth: '450px',
          borderRadius: '12px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.1)',
        }}
      >
        <Space direction="vertical" size="large" style={{ width: '100%', textAlign: 'center' }}>
          {/* Logo */}
          <div>
            <WalletOutlined style={{ fontSize: '48px', color: '#667eea' }} />
            <Title level={2} style={{ marginTop: '16px', marginBottom: '8px' }}>
              AutoSpec
            </Title>
            <Text type="secondary">智能合约自动化审计平台</Text>
          </div>

          {/* 登录说明 */}
          <div style={{ textAlign: 'left' }}>
            <Paragraph>
              <Text strong>使用 Sui 钱包登录：</Text>
            </Paragraph>
            <Paragraph type="secondary" style={{ fontSize: '14px' }}>
              1. 点击下方按钮连接钱包<br />
              2. 在钱包中签名确认<br />
              3. 自动完成登录
            </Paragraph>
          </div>

          {/* 连接钱包按钮 */}
          {loading ? (
            <div style={{ textAlign: 'center', padding: '24px' }}>
              <Spin tip="登录中..." />
            </div>
          ) : (
            <ConnectButton
              connectText="🔗 连接钱包登录"
              className="ant-btn ant-btn-primary ant-btn-lg"
              style={{ width: '100%', height: '48px', fontSize: '16px' }}
            />
          )}
        </Space>
      </Card>
    </div>
  )
}
