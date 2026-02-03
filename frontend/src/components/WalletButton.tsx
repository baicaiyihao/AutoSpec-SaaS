/**
 * 统一钱包按钮（C端用户）
 *
 * 功能：
 * - 未连接：显示「连接钱包」按钮
 * - 已连接：显示钱包地址 + Token余额 + 下拉菜单
 * - 下拉菜单：充值 Token、用户设置、断开钱包（退出登录）
 */
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { ConnectButton, useCurrentAccount, useDisconnectWallet } from '@mysten/dapp-kit'
import { Button, Dropdown, Space, Typography, message } from 'antd'
import {
  WalletOutlined,
  LogoutOutlined,
  SettingOutlined,
  ThunderboltOutlined,
  DollarOutlined,
} from '@ant-design/icons'
import type { MenuProps } from 'antd'
import { useAuth } from '../contexts/AuthContext'

const { Text } = Typography

export default function WalletButton() {
  const currentAccount = useCurrentAccount()
  const { mutate: disconnect } = useDisconnectWallet()
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  // 🔥 监听钱包断开 → 自动退出登录
  useEffect(() => {
    if (user?.wallet_address && !currentAccount) {
      // 钱包用户断开了钱包 → 退出登录
      logout()
      message.info('钱包已断开，已退出登录')
      navigate('/login')
    }
  }, [currentAccount, user, logout, navigate])

  // 未连接钱包
  if (!currentAccount) {
    return (
      <ConnectButton
        connectText="连接钱包"
        className="ant-btn ant-btn-primary"
      />
    )
  }

  const address = currentAccount.address
  const shortAddress = `${address.slice(0, 6)}...${address.slice(-4)}`
  const tokenBalance = user?.token_balance || 0

  const handleDisconnect = () => {
    disconnect()
    logout()
    message.success('已退出登录')
    navigate('/login')
  }

  const items: MenuProps['items'] = [
    {
      key: 'balance',
      label: (
        <Space>
          <ThunderboltOutlined style={{ color: '#faad14' }} />
          <Text strong>{tokenBalance.toLocaleString()} LLM Tokens</Text>
        </Space>
      ),
      disabled: true,
    },
    {
      type: 'divider',
    },
    {
      key: 'purchase',
      icon: <DollarOutlined />,
      label: '充值 Token',
      onClick: () => navigate('/token-purchase'),
    },
    {
      key: 'settings',
      icon: <SettingOutlined />,
      label: '用户设置',
      onClick: () => navigate('/user-settings'),
    },
    {
      type: 'divider',
    },
    {
      key: 'disconnect',
      icon: <LogoutOutlined />,
      label: '断开钱包（退出登录）',
      danger: true,
      onClick: handleDisconnect,
    },
  ]

  return (
    <Dropdown menu={{ items }} placement="bottomRight" trigger={['click']}>
      <Button type="primary" icon={<WalletOutlined />}>
        {shortAddress}
      </Button>
    </Dropdown>
  )
}
