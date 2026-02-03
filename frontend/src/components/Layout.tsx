import { useState, useMemo } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { Layout, Menu, Dropdown, Button, Space } from 'antd'
import {
  DashboardOutlined,
  FolderOutlined,
  FileSearchOutlined,
  AuditOutlined,
  SecurityScanOutlined,
  UserOutlined,
  SettingOutlined,
  TeamOutlined,
  ToolOutlined,
  LogoutOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { useAuth } from '../contexts/AuthContext'
import WalletButton from './WalletButton'

const { Header, Sider, Content } = Layout

export default function MainLayout() {
  const [collapsed, setCollapsed] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const { user, logout, isAdmin } = useAuth()

  const menuItems = useMemo(() => {
    const items = [
      { key: '/dashboard', icon: <DashboardOutlined />, label: '仪表盘' },
      { key: '/token-purchase', icon: <ThunderboltOutlined />, label: 'Token 充值' },
      { key: '/projects', icon: <FolderOutlined />, label: '项目管理' },
      { key: '/audits', icon: <FileSearchOutlined />, label: '审计管理' },
    ]

    if (isAdmin) {
      items.push(
        { key: '/admin/users', icon: <TeamOutlined />, label: '用户管理' },
        { key: '/admin/settings', icon: <ToolOutlined />, label: '系统设置' },
        { key: '/admin/rules', icon: <SafetyCertificateOutlined />, label: '规则管理' },
      )
    }

    return items
  }, [isAdmin])

  // 获取当前选中的菜单项
  const selectedKey = menuItems.find((item) =>
    location.pathname.startsWith(item.key)
  )?.key || '/dashboard'

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const userMenuItems = [
    { key: 'settings', icon: <SettingOutlined />, label: '用户设置' },
    { type: 'divider' as const },
    { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true },
  ]

  const handleUserMenuClick = ({ key }: { key: string }) => {
    if (key === 'settings') navigate('/user-settings')
    if (key === 'logout') handleLogout()
  }

  return (
    <Layout className="min-h-screen">
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={setCollapsed}
        theme="dark"
        className="fixed left-0 top-0 bottom-0 z-10"
      >
        <div className="h-16 flex items-center justify-center">
          <SecurityScanOutlined style={{ fontSize: 24, color: '#60a5fa', marginRight: collapsed ? 0 : 8 }} />
          {!collapsed && (
            <span style={{ color: '#fff', fontSize: 18, fontWeight: 600 }}>
              AutoSpec
            </span>
          )}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout className={`transition-all ${collapsed ? 'ml-20' : 'ml-52'}`}>
        <Header className="bg-white px-6 flex items-center justify-between shadow-sm">
          <div className="flex items-center">
            <AuditOutlined className="text-xl text-gray-500 mr-2" />
            <span className="text-gray-600">智能合约 AI 自动化审计平台</span>
          </div>
          <Space size="middle">
            {/* 钱包用户：显示统一钱包按钮（包含 Token 余额和用户设置） */}
            {user?.wallet_address ? (
              <WalletButton />
            ) : (
              // 管理员用户：显示传统用户按钮
              <Dropdown
                menu={{ items: userMenuItems, onClick: handleUserMenuClick }}
                placement="bottomRight"
              >
                <Button type="text" icon={<UserOutlined />}>
                  {user?.username || '用户'}
                </Button>
              </Dropdown>
            )}
          </Space>
        </Header>
        <Content className="m-4 p-6 bg-white rounded-lg min-h-[calc(100vh-112px)]">
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
