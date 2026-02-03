/**
 * 管理员 - 系统设置页面
 *
 * 子功能Tab:
 * 1. Agent 配置 - 预设模版管理(CRUD) + 逐Agent编辑
 * 2. API Keys - 服务端API Key管理
 * 3. 并发配置
 * 4. 上下文 & LLM
 * 5. 安全 & 风险
 */
import { useState, useEffect } from 'react'
import {
  Tabs, Card, Form, Input, InputNumber, Switch, Button, Select, message,
  Spin, Typography, Divider, Tag, Space, Alert, Modal, Popconfirm,
} from 'antd'
import {
  RobotOutlined, KeyOutlined, ThunderboltOutlined,
  CodeOutlined, ExperimentOutlined,
  PlusOutlined, EditOutlined, DeleteOutlined,
  WalletOutlined, DollarOutlined,
} from '@ant-design/icons'
import { settingsApi } from '../services/api'
import type { SystemSetting, PresetTemplate, ServerApiKeyStatus, PresetAgentConfig } from '../types/auth'

const { Text } = Typography

// ============================================================================
// 常量定义
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

export default function AdminSettings() {
  const [settings, setSettings] = useState<SystemSetting[]>([])
  const [presets, setPresets] = useState<Record<string, PresetTemplate>>({})
  const [apiKeys, setApiKeys] = useState<ServerApiKeyStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm()

  useEffect(() => {
    loadAll()
  }, [])

  const loadAll = async () => {
    try {
      const [settingsData, presetsData, keysData] = await Promise.all([
        settingsApi.get(),
        settingsApi.getPresets(),
        settingsApi.getServerApiKeys(),
      ])
      setSettings(settingsData)
      setPresets(presetsData)
      setApiKeys(keysData)

      // 设置表单值
      const values: Record<string, any> = {}
      for (const s of settingsData) {
        if (s.value_type === 'bool') values[s.key] = s.value === 'true'
        else if (s.value_type === 'int') values[s.key] = parseInt(s.value) || 0
        else if (s.value_type === 'float') values[s.key] = parseFloat(s.value) || 0
        else values[s.key] = s.value
      }
      form.setFieldsValue(values)
    } catch {
      message.error('获取系统设置失败')
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      const values = form.getFieldsValue()
      const updates: Array<{ key: string; value: string }> = []
      for (const s of settings) {
        const val = values[s.key]
        if (val !== undefined) {
          updates.push({ key: s.key, value: String(val) })
        }
      }
      await settingsApi.update(updates)
      message.success('设置已保存')
    } catch (err: any) {
      message.error(err.response?.data?.detail || '保存失败')
    } finally {
      setSaving(false)
    }
  }

  // 选择预设
  const selectPreset = (presetKey: string) => {
    form.setFieldsValue({ default_model_preset: presetKey })
    message.info(`已选择预设: ${presets[presetKey]?.name || presetKey}`)
  }

  if (loading) return <Spin className="block mt-10 mx-auto" />

  // 按category分组
  const byCategory: Record<string, SystemSetting[]> = {}
  for (const s of settings) {
    if (!byCategory[s.category]) byCategory[s.category] = []
    byCategory[s.category].push(s)
  }

  const tabItems = [
    {
      key: 'agent',
      label: <span><RobotOutlined /> Agent 配置</span>,
      children: (
        <AgentConfigTab
          presets={presets}
          onSelectPreset={selectPreset}
          onPresetsChanged={loadAll}
        />
      ),
    },
    {
      key: 'apikeys',
      label: <span><KeyOutlined /> API Keys</span>,
      children: <ApiKeysTab apiKeys={apiKeys} onRefresh={loadAll} />,
    },
    {
      key: 'sui',
      label: <span><WalletOutlined /> Sui 配置</span>,
      children: <SettingsGroup items={byCategory['sui'] || []} title="Sui 区块链配置" />,
    },
    {
      key: 'pricing',
      label: <span><DollarOutlined /> Token 定价</span>,
      children: <SettingsGroup items={byCategory['pricing'] || []} title="Token 定价与 LLM 成本" />,
    },
    {
      key: 'concurrency',
      label: <span><ThunderboltOutlined /> 并发配置</span>,
      children: <SettingsGroup items={byCategory['concurrency'] || []} />,
    },
    {
      key: 'context',
      label: <span><CodeOutlined /> 上下文 & LLM</span>,
      children: (
        <>
          <SettingsGroup items={byCategory['context'] || []} title="上下文组装" />
          <SettingsGroup items={byCategory['truncate'] || []} title="LLM 输入限制 (字符数)" />
        </>
      ),
    },
    {
      key: 'security',
      label: <span><ExperimentOutlined /> 安全 & 风险</span>,
      children: (
        <>
          <SettingsGroup items={byCategory['security'] || []} title="安全扫描" />
          <SettingsGroup items={byCategory['risk'] || []} title="风险阈值" />
        </>
      ),
    },
  ]

  return (
    <div className="max-w-5xl mx-auto">
      <h2 className="text-xl font-bold mb-4">系统设置</h2>
      <Form form={form} layout="vertical">
        <Tabs items={tabItems} tabPosition="left" className="min-h-[500px]" />
        <Divider />
        <Button type="primary" size="large" loading={saving} onClick={handleSave}>
          保存所有设置
        </Button>
      </Form>
    </div>
  )
}


// ============================================================================
// Tab 1: Agent 配置
// ============================================================================

function AgentConfigTab({
  presets, onSelectPreset, onPresetsChanged,
}: {
  presets: Record<string, PresetTemplate>
  onSelectPreset: (key: string) => void
  onPresetsChanged: () => void
}) {
  const [editModalOpen, setEditModalOpen] = useState(false)
  const [editingPreset, setEditingPreset] = useState<{ key: string; data: PresetTemplate } | null>(null)
  const [createMode, setCreateMode] = useState(false)
  const [presetForm] = Form.useForm()
  const [presetSaving, setPresetSaving] = useState(false)

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

  // Modal 渲染后填充表单数据
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
      onPresetsChanged()
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
      onPresetsChanged()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '删除失败')
    }
  }

  return (
    <div>
      {/* 当前预设 */}
      <Card size="small" title="当前预设" className="mb-4">
        <Form.Item name="default_model_preset" label="当前使用的模型预设">
          <Select
            options={Object.entries(presets).map(([k, v]) => ({
              value: k, label: v.name,
            }))}
          />
        </Form.Item>
        <Text type="secondary">
          当前架构: Verifier + Manager(可选) 模式，Phase 2 Auditor → Phase 3 Verifier → Phase 4 WhiteHat
        </Text>
      </Card>

      {/* 预设模版管理 */}
      <Card
        size="small"
        title="预设模版管理"
        className="mb-4"
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
                <Text type="secondary" className="text-xs">{preset.description}</Text>
              </div>
              <Space size="small">
                <Button size="small" type="primary" ghost onClick={() => onSelectPreset(key)}>使用</Button>
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

const SOURCE_LABELS: Record<string, { text: string; color: string }> = {
  both: { text: '环境变量 + Web配置', color: 'green' },
  db: { text: 'Web配置', color: 'green' },
  env: { text: '环境变量', color: 'blue' },
  none: { text: '未配置', color: 'default' },
}

function ApiKeysTab({ apiKeys, onRefresh }: { apiKeys: ServerApiKeyStatus[]; onRefresh: () => void }) {
  const [keyValues, setKeyValues] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)

  const handleSaveKeys = async () => {
    // 只提交有值的 key
    const updates: Record<string, string> = {}
    for (const [k, v] of Object.entries(keyValues)) {
      if (v !== undefined && v !== '') {
        updates[k] = v
      }
    }
    if (Object.keys(updates).length === 0) {
      message.warning('没有修改任何 API Key')
      return
    }
    setSaving(true)
    try {
      await settingsApi.updateServerApiKeys(updates)
      message.success('API Keys 已更新')
      setKeyValues({})
      onRefresh()
    } catch (err: any) {
      message.error(err.response?.data?.detail || '更新失败')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div>
      <Alert
        type="info"
        showIcon
        className="mb-4"
        message="服务端 API Keys 配置"
        description="在此配置的 API Key 会加密存储并立即生效，无需重启服务。优先级高于 .env 文件中的配置。用户级别的共享权限请在【用户管理】中配置。"
      />

      <Card size="small">
        {apiKeys.map(item => {
          const sourceInfo = SOURCE_LABELS[item.source] || SOURCE_LABELS.none
          return (
            <div key={item.key} className="mb-4">
              <div className="flex items-center gap-2 mb-1">
                <Text strong>{item.label}</Text>
                <Tag color={sourceInfo.color}>{sourceInfo.text}</Tag>
              </div>
              <Input.Password
                placeholder={item.source !== 'none' ? '已配置 (输入新值覆盖，留空不变)' : '输入 API Key...'}
                value={keyValues[item.key] || ''}
                onChange={e => setKeyValues(prev => ({ ...prev, [item.key]: e.target.value }))}
              />
            </div>
          )
        })}
        <Button type="primary" onClick={handleSaveKeys} loading={saving}>
          保存 API Keys
        </Button>
      </Card>
    </div>
  )
}


// ============================================================================
// 通用设置组渲染
// ============================================================================

function SettingsGroup({ items, title }: { items: SystemSetting[]; title?: string }) {
  if (items.length === 0) return null
  return (
    <Card size="small" title={title} className="mb-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
        {items.map(item => (
          <Form.Item
            key={item.key}
            name={item.key}
            label={item.description || item.key}
            valuePropName={item.value_type === 'bool' ? 'checked' : 'value'}
          >
            {renderInput(item)}
          </Form.Item>
        ))}
      </div>
    </Card>
  )
}


// ============================================================================
// 输入控件渲染
// ============================================================================



function renderInput(setting: SystemSetting) {
  switch (setting.value_type) {
    case 'bool':
      return <Switch />
    case 'int':
      return <InputNumber className="w-full" min={0} />
    case 'float':
      return <InputNumber className="w-full" step={0.1} min={0} />
    case 'string':
      if (setting.key === 'whitehat_severity_filter') {
        return (
          <Select options={[
            { value: 'critical', label: 'Critical (仅处理严重)' },
            { value: 'high', label: 'High (推荐)' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low (全部处理)' },
          ]} />
        )
      }
      return <Input />
    default:
      return <Input />
  }
}
