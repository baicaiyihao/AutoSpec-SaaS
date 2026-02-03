/**
 * 用户设置页面 - API Keys + 审计配置
 */
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Card, Tabs, Form, Input, Button, Select, InputNumber,
  message, Tag, Space, Typography, Divider, Modal, Popconfirm,
  Table, Radio, Alert,
} from 'antd'
import {
  KeyOutlined, RobotOutlined, ThunderboltOutlined,
  CheckCircleOutlined, CloseCircleOutlined,
  PlusOutlined, EditOutlined, DeleteOutlined,
  LockOutlined,
} from '@ant-design/icons'
import { usersApi, settingsApi } from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import type { ApiKeysStatus, PresetTemplate, PresetAgentConfig } from '../types/auth'

const { Text } = Typography

// ============================================================================
// 常量 (与 AdminSettings 保持一致)
// ============================================================================

const PROVIDER_OPTIONS = [
  { value: 'auto', label: '自动检测' },
  { value: 'dashscope', label: 'DashScope (阿里云)' },
  { value: 'anthropic', label: 'Anthropic (Claude)' },
  { value: 'openai', label: 'OpenAI (GPT)' },
  { value: 'deepseek', label: 'DeepSeek' },
  { value: 'zhipu', label: '智谱AI (GLM)' },
  { value: 'google', label: 'Google (Gemini)' },
  { value: 'ollama', label: 'Ollama (本地)' },
]

const MODEL_OPTIONS: Record<string, Array<{ value: string; label: string }>> = {
  auto: [{ value: 'auto', label: '自动选择' }],
  dashscope: [
    { value: 'qwen-max', label: 'Qwen-Max (32K)' },
    { value: 'qwen-plus', label: 'Qwen-Plus (131K, 高并发)' },
    { value: 'deepseek-v3.2', label: 'DeepSeek-V3.2 (via DashScope)' },
  ],
  anthropic: [
    { value: 'claude-opus-4-5', label: 'Claude Opus 4.5 (最强)' },
    { value: 'claude-sonnet-4-5', label: 'Claude Sonnet 4.5 (推荐)' },
    { value: 'claude-sonnet-4', label: 'Claude Sonnet 4' },
    { value: 'claude-haiku-4-5', label: 'Claude Haiku 4.5 (快速)' },
    { value: 'claude-haiku-3-5', label: 'Claude Haiku 3.5 (最快)' },
  ],
  openai: [
    { value: 'gpt-4o', label: 'GPT-4o' },
    { value: 'gpt-4o-mini', label: 'GPT-4o-mini (低成本)' },
    { value: 'o1', label: 'O1 (推理)' },
  ],
  deepseek: [
    { value: 'deepseek-chat', label: 'DeepSeek-Chat (V3)' },
    { value: 'deepseek-reasoner', label: 'DeepSeek-Reasoner (R1)' },
  ],
  zhipu: [
    { value: 'glm-4.7', label: 'GLM-4.7 (旗舰, 128K输出)' },
    { value: 'glm-4.6', label: 'GLM-4.6 (超强性能)' },
  ],
  google: [
    { value: 'gemini-3-flash', label: 'Gemini 3 Flash' },
    { value: 'gemini-3-pro', label: 'Gemini 3 Pro' },
    { value: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro' },
    { value: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash' },
  ],
  ollama: [
    { value: 'llama3.3:70b', label: 'Llama 3.3 70B' },
    { value: 'llama3.3', label: 'Llama 3.3' },
    { value: 'qwen2.5:72b', label: 'Qwen 2.5 72B' },
  ],
}

const AGENT_ROLES = [
  { key: 'analyst', label: 'Analyst', desc: '代码分析 (Phase 1.6)' },
  { key: 'auditor', label: 'Auditor', desc: '漏洞扫描 (Phase 2)' },
  { key: 'verifier', label: 'Verifier', desc: '多视角验证 (Phase 3)' },
  { key: 'manager', label: 'Manager', desc: '管理裁决 (Phase 3/5)' },
  { key: 'white_hat', label: 'WhiteHat', desc: '漏洞利用验证 (Phase 4)' },
  { key: 'review', label: 'Review', desc: '安全审查、误报过滤' },
]


// ============================================================================
// 主组件
// ============================================================================

export default function UserSettings() {
  const { user } = useAuth()

  const tabs = [
    { key: 'token-usage', label: <span><ThunderboltOutlined /> Token 统计</span>, children: <TokenUsageTab /> },
    { key: 'api-keys', label: <span><KeyOutlined /> API Keys</span>, children: <ApiKeysTab /> },
    { key: 'audit-config', label: <span><RobotOutlined /> 审计配置</span>, children: <AuditConfigTab /> },
  ]

  // 管理员用户显示修改密码选项（钱包用户无需密码）
  if (!user?.wallet_address) {
    tabs.push({
      key: 'change-password',
      label: <span><LockOutlined /> 修改密码</span>,
      children: <ChangePasswordTab />
    })
  }

  return (
    <div className="max-w-4xl mx-auto">
      <h2 className="text-xl font-bold mb-4">用户设置</h2>
      <Tabs items={tabs} />
    </div>
  )
}


// ============================================================================
// Tab 0: Token 使用统计
// ============================================================================

function TokenUsageTab() {
  const navigate = useNavigate()
  const { user, updateUser } = useAuth()
  const [paymentMode, setPaymentMode] = useState<'own_key' | 'platform_token'>(user?.payment_mode || 'own_key')
  const [switching, setSwitching] = useState(false)

  useEffect(() => {
    if (user?.payment_mode) {
      setPaymentMode(user.payment_mode)
    }
  }, [user?.payment_mode])

  const handlePaymentModeChange = async (mode: 'own_key' | 'platform_token') => {
    setSwitching(true)
    try {
      await usersApi.updatePaymentMode({ payment_mode: mode })
      setPaymentMode(mode)
      updateUser({ payment_mode: mode })
      message.success('付费模式已更新')
    } catch {
      message.error('更新付费模式失败')
    } finally {
      setSwitching(false)
    }
  }

  const formatNumber = (n: number) => n.toLocaleString()

  return (
    <div className="space-y-4">
      {/* 付费模式选择 */}
      <Card size="small" title="💳 付费模式">
        <Radio.Group
          value={paymentMode}
          onChange={(e) => handlePaymentModeChange(e.target.value)}
          disabled={switching}
          className="w-full"
        >
          <Space direction="vertical" className="w-full">
            <Radio value="own_key" className="w-full">
              <div className="flex flex-col">
                <Text strong>使用自己的 API Key</Text>
                <Text type="secondary" className="text-xs">
                  直接向 LLM 供应商付费，系统仅统计使用量
                </Text>
              </div>
            </Radio>
            <Radio value="platform_token" className="w-full">
              <div className="flex flex-col">
                <Text strong>使用平台 Token 余额</Text>
                <Text type="secondary" className="text-xs">
                  使用购买的 Token 余额，平台统一调用 LLM（需要先充值）
                </Text>
              </div>
            </Radio>
          </Space>
        </Radio.Group>
      </Card>

      {/* Token 余额概览 */}
      <Card size="small" title="💰 Token 余额">
        <div className="text-center p-4">
          <div className="mb-4">
            <ThunderboltOutlined style={{ fontSize: '48px', color: '#faad14' }} />
          </div>
          <div className="text-4xl font-bold text-blue-600 mb-2">
            {formatNumber(user?.token_balance || 0)}
          </div>
          <div className="text-gray-500 mb-4">可用 LLM Tokens</div>
          <Button type="primary" onClick={() => navigate('/token-purchase')}>
            充值 Token
          </Button>
        </div>
      </Card>

      {/* Token 使用统计 */}
      <Card size="small" title="📊 使用统计">
        <div className="grid grid-cols-3 gap-4 mb-4">
          <div className="text-center p-4 bg-gray-50 rounded">
            <div className="text-2xl font-bold text-gray-800">
              {formatNumber(user?.tokens_used || 0)}
            </div>
            <div className="text-gray-500 text-sm mt-1">总消耗</div>
          </div>
          <div className="text-center p-4 bg-blue-50 rounded">
            <div className="text-2xl font-bold text-blue-600">
              {formatNumber(user?.tokens_used_own_key || 0)}
            </div>
            <div className="text-gray-500 text-sm mt-1">自有 API Key</div>
          </div>
          <div className="text-center p-4 bg-green-50 rounded">
            <div className="text-2xl font-bold text-green-600">
              {formatNumber(user?.tokens_used_platform || 0)}
            </div>
            <div className="text-gray-500 text-sm mt-1">平台 Token</div>
          </div>
        </div>

        <Divider className="my-4" />

        <div className="text-sm text-gray-500">
          <div className="flex justify-between mb-2">
            <span>当前模式：</span>
            <Text strong>
              {paymentMode === 'own_key' ? '使用自己的 API Key' : '使用平台 Token'}
            </Text>
          </div>
          {paymentMode === 'platform_token' && (
            <div className="flex justify-between">
              <span>剩余余额：</span>
              <Text strong className="text-blue-600">
                {formatNumber(user?.token_balance || 0)} tokens
              </Text>
            </div>
          )}
        </div>
      </Card>

      {/* 使用提示 */}
      <Card size="small">
        <Alert
          message="💡 使用说明"
          description={
            <ul className="list-disc pl-5 text-sm space-y-1">
              <li><strong>自有 API Key 模式</strong>: 需要在「API Keys」标签配置您的 API Key，审计时直接调用您的账号，费用由 LLM 供应商收取</li>
              <li><strong>平台 Token 模式</strong>: 使用您购买的 Token 余额，审计时实时扣费，Token 不足时审计会自动终止</li>
              <li>两种模式的消耗分开统计，可随时切换（不影响已统计的数据）</li>
            </ul>
          }
          type="info"
          showIcon
        />
      </Card>
    </div>
  )
}

// ============================================================================
// Tab 1: 审计配置
// ============================================================================

function AuditConfigTab() {
  const [presets, setPresets] = useState<Record<string, PresetTemplate>>({})
  const [currentPreset, setCurrentPreset] = useState<string>('_system')
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [editingPreset, setEditingPreset] = useState<{ key: string; data: PresetTemplate } | null>(null)
  const [createMode, setCreateMode] = useState(false)
  const [presetForm] = Form.useForm()
  const [presetSaving, setPresetSaving] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [configData, presetsData] = await Promise.all([
        usersApi.getAuditConfig(),
        settingsApi.getPresets(),
      ])
      setPresets(presetsData)
      setCurrentPreset(configData.model_preset || '_system')
    } catch {
      message.error('获取配置失败')
    }
  }

  const selectPreset = async (presetKey: string) => {
    try {
      await usersApi.updateAuditConfig({ model_preset: presetKey })
      setCurrentPreset(presetKey)
      const label = presetKey === '_system' ? '跟随系统设置' : (presets[presetKey]?.name || presetKey)
      message.success(`已选择: ${label}`)
    } catch {
      message.error('更新失败')
    }
  }

  const openCreateModal = () => {
    setCreateMode(true)
    setEditingPreset(null)
    setEditModalOpen(true)
  }

  const openEditModal = (key: string, preset: PresetTemplate) => {
    setCreateMode(false)
    setEditingPreset({ key, data: preset })
    setEditModalOpen(true)
  }

  const handleModalAfterOpen = (open: boolean) => {
    if (!open) return
    if (createMode) {
      presetForm.setFieldsValue({
        key: '',
        name: '',
        description: '',
        ...Object.fromEntries(AGENT_ROLES.flatMap(r => [
          [`agent_${r.key}_provider`, 'auto'],
          [`agent_${r.key}_model`, 'auto'],
          [`agent_${r.key}_max_tokens`, 0],
          [`agent_${r.key}_fallback_provider`, ''],
          [`agent_${r.key}_fallback_model`, ''],
        ])),
      })
    } else if (editingPreset) {
      const preset = editingPreset.data
      presetForm.setFieldsValue({
        key: editingPreset.key,
        name: preset.name,
        description: preset.description,
        ...Object.fromEntries(
          Object.entries(preset.agents).flatMap(([role, cfg]) => [
            [`agent_${role}_provider`, cfg.provider],
            [`agent_${role}_model`, cfg.model],
            [`agent_${role}_max_tokens`, cfg.max_tokens || 0],
            [`agent_${role}_fallback_provider`, cfg.fallback_provider || ''],
            [`agent_${role}_fallback_model`, cfg.fallback_model || ''],
          ])
        ),
      })
    }
  }

  const handlePresetSave = async () => {
    try {
      const values = await presetForm.validateFields()
      setPresetSaving(true)

      const agents: Record<string, PresetAgentConfig> = {}
      for (const role of AGENT_ROLES) {
        const cfg: PresetAgentConfig = {
          provider: values[`agent_${role.key}_provider`] || 'auto',
          model: values[`agent_${role.key}_model`] || 'auto',
        }
        const maxTokens = values[`agent_${role.key}_max_tokens`]
        if (maxTokens && maxTokens > 0) cfg.max_tokens = maxTokens
        const fbProvider = values[`agent_${role.key}_fallback_provider`]
        if (fbProvider) cfg.fallback_provider = fbProvider
        const fbModel = values[`agent_${role.key}_fallback_model`]
        if (fbModel) cfg.fallback_model = fbModel
        agents[role.key] = cfg
      }

      if (createMode) {
        await settingsApi.createPreset({
          key: values.key,
          name: values.name,
          description: values.description || '',
          agents,
        })
        message.success(`预设 "${values.name}" 已创建`)
      } else if (editingPreset) {
        await settingsApi.updatePreset(editingPreset.key, {
          name: values.name,
          description: values.description || '',
          agents,
        })
        message.success(`预设 "${values.name}" 已更新`)
      }

      setEditModalOpen(false)
      loadData()
    } catch (err: any) {
      if (err.response?.data?.detail) {
        message.error(err.response.data.detail)
      }
    } finally {
      setPresetSaving(false)
    }
  }

  const handleDeletePreset = async (key: string) => {
    try {
      await settingsApi.deletePreset(key)
      message.success('预设已删除')
      loadData()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '删除失败')
    }
  }

  const presetOptions = [
    { value: '_system', label: '跟随系统设置' },
    ...Object.entries(presets).map(([k, v]) => ({ value: k, label: v.name })),
  ]

  return (
    <div>
      {/* 当前预设 */}
      <Card size="small" title="当前预设" className="mb-4">
        <div className="flex items-center gap-3">
          <Select
            value={currentPreset}
            options={presetOptions}
            onChange={selectPreset}
            className="flex-1"
          />
        </div>
        <Text type="secondary" className="block mt-2">
          {currentPreset === '_system'
            ? '使用管理员配置的系统默认预设'
            : `当前架构: Verifier + Manager(可选) 模式，Phase 2 Auditor → Phase 3 Verifier → Phase 4 WhiteHat`
          }
        </Text>
      </Card>

      {/* 预设模版管理 */}
      <Card
        size="small"
        title="预设模版管理"
        extra={
          <Button type="primary" icon={<PlusOutlined />} size="small" onClick={openCreateModal}>
            新建预设
          </Button>
        }
      >
        <Text type="secondary" className="block mb-3">
          点击"使用"切换当前预设，点击"编辑"修改预设配置（内置预设编辑后会保存为自定义副本）
        </Text>
        <div className="space-y-2">
          {Object.entries(presets).map(([key, preset]) => (
            <div key={key} className="flex items-center justify-between p-2 border rounded hover:bg-gray-50">
              <div className="flex items-center gap-2">
                <Text strong>{preset.name}</Text>
                {preset.builtin ? (
                  <Tag color="blue">内置</Tag>
                ) : (
                  <Tag color="green">自定义</Tag>
                )}
                {currentPreset === key && <Tag color="orange">当前</Tag>}
                <Text type="secondary" className="text-xs">{preset.description}</Text>
              </div>
              <Space size="small">
                <Button size="small" type="primary" ghost onClick={() => selectPreset(key)}>使用</Button>
                <Button size="small" icon={<EditOutlined />} onClick={() => openEditModal(key, preset)}>
                  编辑
                </Button>
                {!preset.builtin && (
                  <Popconfirm title="确定删除此预设？" onConfirm={() => handleDeletePreset(key)}>
                    <Button size="small" danger icon={<DeleteOutlined />} />
                  </Popconfirm>
                )}
              </Space>
            </div>
          ))}
        </div>
      </Card>

      {/* 预设编辑/创建 Modal */}
      <Modal
        title={createMode ? '新建预设' : `编辑预设: ${editingPreset?.data.name || ''}`}
        open={editModalOpen}
        onCancel={() => setEditModalOpen(false)}
        onOk={handlePresetSave}
        confirmLoading={presetSaving}
        width={700}
        okText={createMode ? '创建' : '保存'}
        afterOpenChange={handleModalAfterOpen}
      >
        <Form form={presetForm} layout="vertical" className="mt-4">
          {createMode && (
            <Form.Item
              name="key"
              label="预设标识 (唯一Key)"
              rules={[
                { required: true, message: '请输入预设标识' },
                { pattern: /^[a-z0-9_]+$/, message: '仅支持小写字母、数字和下划线' },
              ]}
            >
              <Input placeholder="my_preset" />
            </Form.Item>
          )}
          <Form.Item name="name" label="预设名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input placeholder="我的自定义配置" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input placeholder="配置描述..." />
          </Form.Item>
          <Divider>Agent 模型配置</Divider>
          {AGENT_ROLES.map(role => {
            const providerField = `agent_${role.key}_provider`
            const modelField = `agent_${role.key}_model`
            const fbProviderField = `agent_${role.key}_fallback_provider`
            const fbModelField = `agent_${role.key}_fallback_model`
            return (
              <div key={role.key} className="mb-4 p-3 border rounded bg-gray-50">
                <Text strong className="block mb-2">{role.label} <Text type="secondary" className="text-xs font-normal">({role.desc})</Text></Text>
                <div className="grid grid-cols-3 gap-2 mb-2">
                  <Form.Item name={providerField} label="提供商" className="mb-0">
                    <Select options={PROVIDER_OPTIONS} size="small"
                      onChange={(val: string) => {
                        const models = MODEL_OPTIONS[val] || MODEL_OPTIONS.auto
                        presetForm.setFieldsValue({ [modelField]: models[0]?.value || 'auto' })
                      }}
                    />
                  </Form.Item>
                  <Form.Item noStyle dependencies={[providerField]}>
                    {() => {
                      const prov = presetForm.getFieldValue(providerField) || 'auto'
                      const opts = prov === 'auto'
                        ? [{ value: 'auto', label: '自动选择' }]
                        : (MODEL_OPTIONS[prov] || MODEL_OPTIONS.auto)
                      return (
                        <Form.Item name={modelField} label="模型" className="mb-0">
                          <Select options={opts} size="small" />
                        </Form.Item>
                      )
                    }}
                  </Form.Item>
                  <Form.Item name={`agent_${role.key}_max_tokens`} label="Max Tokens" className="mb-0">
                    <InputNumber className="w-full" size="small" min={0} placeholder="0=默认" />
                  </Form.Item>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Form.Item name={fbProviderField} label="降级提供商" className="mb-0">
                    <Select options={[{ value: '', label: '无' }, ...PROVIDER_OPTIONS]} size="small" allowClear
                      onChange={(val: string) => {
                        if (!val) {
                          presetForm.setFieldsValue({ [fbModelField]: '' })
                        } else {
                          const models = MODEL_OPTIONS[val] || MODEL_OPTIONS.auto
                          presetForm.setFieldsValue({ [fbModelField]: models[0]?.value || '' })
                        }
                      }}
                    />
                  </Form.Item>
                  <Form.Item noStyle dependencies={[fbProviderField]}>
                    {() => {
                      const fbProv = presetForm.getFieldValue(fbProviderField) || ''
                      if (!fbProv) {
                        return (
                          <Form.Item name={fbModelField} label="降级模型" className="mb-0">
                            <Select options={[{ value: '', label: '无' }]} size="small" disabled />
                          </Form.Item>
                        )
                      }
                      const fbOpts = [{ value: '', label: '无' }, ...(MODEL_OPTIONS[fbProv] || MODEL_OPTIONS.auto)]
                      return (
                        <Form.Item name={fbModelField} label="降级模型" className="mb-0">
                          <Select options={fbOpts} size="small" />
                        </Form.Item>
                      )
                    }}
                  </Form.Item>
                </div>
              </div>
            )
          })}
        </Form>
      </Modal>
    </div>
  )
}


// ============================================================================
// Tab 2: API Keys
// ============================================================================

function ApiKeysTab() {
  const [status, setStatus] = useState<ApiKeysStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [form] = Form.useForm()

  useEffect(() => {
    loadStatus()
  }, [])

  const loadStatus = async () => {
    try {
      const data = await usersApi.getApiKeys()
      setStatus(data)
    } catch {
      message.error('获取 API Key 状态失败')
    }
  }

  const handleSubmit = async (values: Record<string, string>) => {
    setLoading(true)
    try {
      const update: Record<string, string> = {}
      for (const [key, val] of Object.entries(values)) {
        if (val !== undefined && val !== '') {
          update[key] = val
        }
      }
      if (Object.keys(update).length === 0) {
        message.warning('没有要更新的内容')
        return
      }
      await usersApi.updateApiKeys(update)
      message.success('API Keys 已更新')
      form.resetFields()
      await loadStatus()
    } catch {
      message.error('更新失败')
    } finally {
      setLoading(false)
    }
  }

  const keys = [
    { name: 'dashscope', label: 'DashScope (通义千问)' },
    { name: 'anthropic', label: 'Anthropic (Claude)' },
    { name: 'openai', label: 'OpenAI (GPT)' },
    { name: 'deepseek', label: 'DeepSeek' },
    { name: 'zhipu', label: 'ZhipuAI (智谱)' },
  ]

  return (
    <Card>
      <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded">
        <Text className="text-blue-700">
          <strong>💡 配置您的 API Keys</strong>
        </Text>
        <div className="text-sm text-gray-600 mt-1">
          配置您自己的 API Keys 用于审计任务。至少配置一个提供商的 Key。
        </div>
      </div>

      <div className="mb-4">
        <Space wrap>
          {status && keys.map(k => (
            <Tag
              key={k.name}
              icon={status[k.name as keyof ApiKeysStatus] ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
              color={status[k.name as keyof ApiKeysStatus] ? 'success' : 'default'}
            >
              {k.label}
            </Tag>
          ))}
        </Space>
      </div>

      <Form form={form} onFinish={handleSubmit} layout="vertical">
        {keys.map(k => (
          <Form.Item key={k.name} name={k.name} label={k.label}>
            <Input.Password placeholder={`输入新的 ${k.label} Key（留空不更新）`} />
          </Form.Item>
        ))}
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>
            更新 API Keys
          </Button>
        </Form.Item>
      </Form>
    </Card>
  )
}


// ============================================================================
// Tab: 修改密码（仅管理员）
// ============================================================================

function ChangePasswordTab() {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (values: { old_password: string; new_password: string; confirm_password: string }) => {
    if (values.new_password !== values.confirm_password) {
      message.error('两次输入的新密码不一致')
      return
    }

    setLoading(true)
    try {
      await usersApi.changePassword({
        old_password: values.old_password,
        new_password: values.new_password,
      })
      message.success('密码修改成功')
      form.resetFields()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '密码修改失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card size="small">
      <Form
        form={form}
        layout="vertical"
        onFinish={handleSubmit}
        style={{ maxWidth: '500px' }}
      >
        <Form.Item
          label="原密码"
          name="old_password"
          rules={[{ required: true, message: '请输入原密码' }]}
        >
          <Input.Password placeholder="请输入原密码" />
        </Form.Item>

        <Form.Item
          label="新密码"
          name="new_password"
          rules={[
            { required: true, message: '请输入新密码' },
            { min: 8, message: '密码长度至少 8 位' },
          ]}
        >
          <Input.Password placeholder="请输入新密码（至少 8 位）" />
        </Form.Item>

        <Form.Item
          label="确认新密码"
          name="confirm_password"
          rules={[{ required: true, message: '请再次输入新密码' }]}
        >
          <Input.Password placeholder="请再次输入新密码" />
        </Form.Item>

        <Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>
            修改密码
          </Button>
        </Form.Item>
      </Form>

      <Divider />

      <Alert
        message="密码要求"
        description={
          <ul className="list-disc pl-5 text-sm">
            <li>密码长度至少 8 位</li>
            <li>建议包含大小写字母、数字和特殊字符</li>
            <li>修改密码后需要重新登录</li>
          </ul>
        }
        type="info"
        showIcon
      />
    </Card>
  )
}

// ============================================================================
// Tab: 钱包管理
// ============================================================================

interface TokenPurchaseRecord {
  id: string
  transaction_digest: string
  sui_amount: number
  usd_amount: number
  token_amount: number
  status: string
  created_at: string
}

