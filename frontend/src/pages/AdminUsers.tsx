/**
 * 管理员 - 用户管理页面
 */
import { useState, useEffect } from 'react'
import { Table, Button, Tag, Space, Popconfirm, Select, message, Card, Radio, InputNumber, Modal, Tooltip, Progress, Switch } from 'antd'
import { DeleteOutlined, UserOutlined, EditOutlined, ReloadOutlined, DollarOutlined } from '@ant-design/icons'
import { usersApi, settingsApi } from '../services/api'
import type { UserInfo } from '../types/auth'
import { useAuth } from '../contexts/AuthContext'
import { formatDateTime } from '../utils/time'

export default function AdminUsers() {
  const [users, setUsers] = useState<UserInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [registrationMode, setRegistrationMode] = useState<string>('open')
  const { user: currentUser } = useAuth()

  // Token 额度管理
  const [quotaModalOpen, setQuotaModalOpen] = useState(false)
  const [editingUser, setEditingUser] = useState<UserInfo | null>(null)
  const [quotaValue, setQuotaValue] = useState<number | null>(null)
  const [quotaSaving, setQuotaSaving] = useState(false)

  useEffect(() => {
    loadUsers()
    loadRegistrationMode()
  }, [])

  const loadUsers = async () => {
    setLoading(true)
    try {
      const data = await usersApi.list()
      setUsers(data.users)
    } catch (err) {
      message.error('获取用户列表失败')
    } finally {
      setLoading(false)
    }
  }

  const loadRegistrationMode = async () => {
    try {
      const settings = await settingsApi.get()
      const mode = settings.find(s => s.key === 'registration_mode')
      if (mode) setRegistrationMode(mode.value)
    } catch {
      // ignore
    }
  }

  const handleRegistrationModeChange = async (value: string) => {
    try {
      await settingsApi.update([{ key: 'registration_mode', value }])
      setRegistrationMode(value)
      message.success(value === 'review' ? '已开启注册审核' : '已关闭注册审核')
    } catch {
      message.error('更新失败')
    }
  }

  const handleRoleChange = async (userId: string, role: string) => {
    try {
      await usersApi.updateRole(userId, role)
      message.success('角色已更新')
      await loadUsers()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '更新失败')
    }
  }

  const handleToggleStatus = async (userId: string, currentActive: boolean) => {
    try {
      await usersApi.updateStatus(userId, !currentActive)
      message.success(currentActive ? '已禁用' : '已启用')
      await loadUsers()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '操作失败')
    }
  }

  const handleToggleSharedApiKeys = async (userId: string, currentAllowed: boolean) => {
    try {
      await usersApi.updateSharedApiKeys(userId, !currentAllowed)
      message.success(currentAllowed ? '已禁止使用共享 API Keys' : '已允许使用共享 API Keys')
      await loadUsers()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '操作失败')
    }
  }

  const handleDelete = async (userId: string) => {
    try {
      await usersApi.delete(userId)
      message.success('用户已删除')
      await loadUsers()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '删除失败')
    }
  }

  // Token 额度管理
  const openQuotaModal = (user: UserInfo) => {
    setEditingUser(user)
    setQuotaValue(user.token_quota ?? null)
    setQuotaModalOpen(true)
  }

  const handleQuotaSave = async () => {
    if (!editingUser) return
    setQuotaSaving(true)
    try {
      await usersApi.setUserTokenQuota(editingUser.id, quotaValue)
      message.success(quotaValue === null ? '已设为无限额度' : `额度已设为 ${quotaValue.toLocaleString()}`)
      setQuotaModalOpen(false)
      await loadUsers()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '设置失败')
    } finally {
      setQuotaSaving(false)
    }
  }

  const handleResetUsage = async (userId: string) => {
    try {
      await usersApi.resetUserTokenUsage(userId)
      message.success('使用量已重置')
      await loadUsers()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '重置失败')
    }
  }

  const formatNumber = (n: number) => n?.toLocaleString() || '0'

  const columns = [
    {
      title: '用户名',
      dataIndex: 'username',
      key: 'username',
      render: (text: string, record: UserInfo) => (
        <Space>
          <UserOutlined />
          {text}
          {record.id === currentUser?.id && <Tag color="blue">当前</Tag>}
        </Space>
      ),
    },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      render: (role: string, record: UserInfo) => {
        if (record.id === currentUser?.id) {
          return <Tag color={role === 'admin' ? 'red' : 'blue'}>{role === 'admin' ? '管理员' : '用户'}</Tag>
        }
        return (
          <Select
            size="small"
            value={role}
            onChange={(val) => handleRoleChange(record.id, val)}
            options={[
              { value: 'admin', label: '管理员' },
              { value: 'user', label: '用户' },
            ]}
            style={{ width: 90 }}
          />
        )
      },
    },
    {
      title: '状态',
      dataIndex: 'is_active',
      key: 'is_active',
      width: 80,
      render: (active: boolean) => (
        <Tag color={active ? 'green' : 'red'}>{active ? '启用' : '禁用'}</Tag>
      ),
    },
    {
      title: '共享API Keys',
      dataIndex: 'allow_shared_api_keys',
      key: 'allow_shared_api_keys',
      width: 120,
      render: (allowed: boolean, record: UserInfo) => (
        <Tooltip title={allowed ? '允许使用管理员配置的API Keys' : '必须使用自己的API Keys'}>
          <Switch
            size="small"
            checked={allowed}
            onChange={() => handleToggleSharedApiKeys(record.id, allowed)}
            checkedChildren="允许"
            unCheckedChildren="禁止"
          />
        </Tooltip>
      ),
    },
    {
      title: 'Token 额度',
      key: 'token_quota',
      width: 200,
      render: (_: unknown, record: UserInfo) => {
        const quota = record.token_quota
        const used = record.tokens_used || 0
        const isUnlimited = quota === null || quota === undefined
        const percent = isUnlimited ? 0 : (quota > 0 ? (used / quota) * 100 : 100)

        return (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span>{formatNumber(used)} / {isUnlimited ? '∞' : formatNumber(quota)}</span>
              <Space size={4}>
                <Tooltip title="设置额度">
                  <Button size="small" type="text" icon={<EditOutlined />} onClick={() => openQuotaModal(record)} />
                </Tooltip>
                {used > 0 && (
                  <Popconfirm title="确定重置使用量？" onConfirm={() => handleResetUsage(record.id)}>
                    <Tooltip title="重置使用量">
                      <Button size="small" type="text" icon={<ReloadOutlined />} />
                    </Tooltip>
                  </Popconfirm>
                )}
              </Space>
            </div>
            {!isUnlimited && (
              <Progress
                percent={Math.min(100, percent)}
                size="small"
                showInfo={false}
                status={percent > 90 ? 'exception' : percent > 70 ? 'active' : 'success'}
              />
            )}
          </div>
        )
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (t: string) => formatDateTime(t),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: UserInfo) => {
        if (record.id === currentUser?.id) return null
        return (
          <Space>
            <Button
              size="small"
              onClick={() => handleToggleStatus(record.id, record.is_active)}
            >
              {record.is_active ? '禁用' : '启用'}
            </Button>
            <Popconfirm title="确定删除该用户？" onConfirm={() => handleDelete(record.id)}>
              <Button size="small" danger icon={<DeleteOutlined />} />
            </Popconfirm>
          </Space>
        )
      },
    },
  ]

  return (
    <div>
      <h2 className="text-xl font-bold mb-4">用户管理</h2>

      <Card size="small" className="mb-4">
        <div className="flex items-center gap-4">
          <span className="font-medium">用户注册:</span>
          <Radio.Group
            value={registrationMode}
            onChange={e => handleRegistrationModeChange(e.target.value)}
            optionType="button"
            buttonStyle="solid"
            options={[
              { value: 'open', label: '自动通过' },
              { value: 'review', label: '需要审核' },
            ]}
          />
          <span className="text-gray-400 text-sm">
            {registrationMode === 'review' ? '新用户注册后需管理员手动启用' : '新用户注册后立即可用'}
          </span>
        </div>
      </Card>

      <Table
        columns={columns}
        dataSource={users}
        rowKey="id"
        loading={loading}
        pagination={false}
      />

      {/* Token 额度设置 Modal */}
      <Modal
        title={<span><DollarOutlined /> 设置 Token 额度 - {editingUser?.username}</span>}
        open={quotaModalOpen}
        onCancel={() => setQuotaModalOpen(false)}
        onOk={handleQuotaSave}
        confirmLoading={quotaSaving}
        okText="保存"
      >
        <div className="py-4">
          <div className="mb-4">
            <Radio.Group
              value={quotaValue === null ? 'unlimited' : 'limited'}
              onChange={(e) => setQuotaValue(e.target.value === 'unlimited' ? null : 1000000)}
            >
              <Radio value="unlimited">无限额度</Radio>
              <Radio value="limited">设置上限</Radio>
            </Radio.Group>
          </div>

          {quotaValue !== null && (
            <div>
              <label className="block text-sm text-gray-600 mb-2">Token 额度上限</label>
              <InputNumber
                value={quotaValue}
                onChange={(v) => setQuotaValue(v)}
                min={0}
                step={100000}
                formatter={(value) => `${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}
                parser={(value) => Number(value?.replace(/,/g, '') || 0)}
                className="w-full"
                addonAfter="tokens"
              />
              <div className="mt-2 text-xs text-gray-400">
                建议值：100,000 (小项目) / 500,000 (中项目) / 1,000,000 (大项目)
              </div>
            </div>
          )}

          {editingUser && (
            <div className="mt-4 p-3 bg-gray-50 rounded text-sm">
              <div>当前已使用: <strong>{formatNumber(editingUser.tokens_used || 0)}</strong> tokens</div>
              {editingUser.token_quota !== null && editingUser.token_quota !== undefined && (
                <div>当前额度: <strong>{formatNumber(editingUser.token_quota)}</strong> tokens</div>
              )}
            </div>
          )}
        </div>
      </Modal>
    </div>
  )
}
