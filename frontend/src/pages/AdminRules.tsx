/**
 * 规则管理页面
 *
 * 按链分类展示，点击进入查看详细规则
 */
import { useEffect, useState } from 'react'
import {
  Card,
  Table,
  Switch,
  Tag,
  Input,
  Select,
  Space,
  Button,
  Statistic,
  Row,
  Col,
  message,
  Tooltip,
  Modal,
  Form,
  Alert,
  Popconfirm,
  Checkbox,
  Breadcrumb,
} from 'antd'
import {
  SearchOutlined,
  ReloadOutlined,
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  CodeOutlined,
  DatabaseOutlined,
  InfoCircleOutlined,
  ArrowLeftOutlined,
} from '@ant-design/icons'
import { rulesApi, SystemRule, CustomExclusion, RuleStats, MatchConfig } from '../services/api'

interface BlockchainInfo {
  id: string
  name: string
  description: string
  color: string
  ruleCount: number
  enabledCount: number
  customCount: number
}

const CATEGORY_CONFIG: Record<string, { label: string; color: string }> = {
  language_protection: { label: '语言保护', color: 'blue' },
  access_control: { label: '访问控制', color: 'green' },
  arithmetic: { label: '算术安全', color: 'orange' },
  resource_safety: { label: '资源安全', color: 'purple' },
  design_pattern: { label: '设计模式', color: 'cyan' },
  code_quality: { label: '代码质量', color: 'default' },
  defi_specific: { label: 'DeFi 特定', color: 'gold' },
  production_pattern: { label: '生产模式', color: 'lime' },
  semantic: { label: '语义分析', color: 'magenta' },
  custom: { label: '自定义', color: 'volcano' },
}

const SEVERITY_OPTIONS = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
  { label: 'Advisory', value: 'advisory' },
]

// 自定义规则示例模板
const CUSTOM_RULE_EXAMPLES = [
  {
    name: '排除测试文件漏洞',
    description: '排除 tests/ 目录下的所有漏洞报告',
    match_config: {
      file_pattern: 'tests/.*\\.move$',
      match_all: false,
    },
  },
  {
    name: '排除低严重性漏洞',
    description: '排除 LOW 和 ADVISORY 级别的漏洞',
    match_config: {
      severity_in: ['low', 'advisory'],
      match_all: false,
    },
  },
  {
    name: '排除 Mock 函数漏洞',
    description: '排除函数名包含 mock/test/dummy 的漏洞',
    match_config: {
      function_pattern: '(mock|test|dummy)',
      match_all: false,
    },
  },
]

type ViewMode = 'overview' | 'blockchain-system' | 'blockchain-custom'

export default function AdminRules() {
  // 视图状态
  const [viewMode, setViewMode] = useState<ViewMode>('overview')
  const [selectedBlockchain, setSelectedBlockchain] = useState<string | null>(null)

  // 系统规则状态
  const [loading, setLoading] = useState(true)
  const [rules, setRules] = useState<SystemRule[]>([])
  const [_stats, setStats] = useState<RuleStats | null>(null) // 保留用于后续扩展
  const [searchText, setSearchText] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<string | undefined>()
  const [enabledFilter, setEnabledFilter] = useState<boolean | undefined>()

  // 自定义规则状态
  const [customRules, setCustomRules] = useState<CustomExclusion[]>([])
  const [modalVisible, setModalVisible] = useState(false)
  const [editingRule, setEditingRule] = useState<CustomExclusion | null>(null)
  const [form] = Form.useForm()

  // 链统计信息
  const [blockchainInfos, setBlockchainInfos] = useState<BlockchainInfo[]>([])

  useEffect(() => {
    loadOverviewData()
  }, [])

  const loadOverviewData = async () => {
    try {
      setLoading(true)
      const [rulesData, statsData, customData] = await Promise.all([
        rulesApi.listSystemRules(),
        rulesApi.getSystemRulesStats(),
        rulesApi.listCustomExclusions(),
      ])
      setRules(rulesData)
      setStats(statsData)
      setCustomRules(customData)

      // 计算链统计信息
      const suiRules = rulesData.filter((r: SystemRule) => r.blockchain === 'sui')
      const suiCustom = customData.filter((r: CustomExclusion) => r.blockchain === 'sui')

      const infos: BlockchainInfo[] = [
        {
          id: 'sui',
          name: 'Sui Move',
          description: 'Sui 区块链 Move 智能合约安全规则',
          color: '#6fbcf0',
          ruleCount: suiRules.length,
          enabledCount: suiRules.filter((r: SystemRule) => r.is_enabled).length,
          customCount: suiCustom.length,
        },
      ]
      setBlockchainInfos(infos)
    } catch (error) {
      console.error('Failed to load data:', error)
      message.error('加载数据失败')
    } finally {
      setLoading(false)
    }
  }

  const loadBlockchainRules = async (blockchain: string) => {
    try {
      setLoading(true)
      const [rulesData, customData] = await Promise.all([
        rulesApi.listSystemRules({ blockchain }),
        rulesApi.listCustomExclusions({ blockchain }),
      ])
      setRules(rulesData)
      setCustomRules(customData)
    } catch (error) {
      console.error('Failed to load rules:', error)
      message.error('加载规则失败')
    } finally {
      setLoading(false)
    }
  }

  const handleEnterBlockchain = (blockchain: string, tab: 'system' | 'custom') => {
    setSelectedBlockchain(blockchain)
    setViewMode(tab === 'system' ? 'blockchain-system' : 'blockchain-custom')
    loadBlockchainRules(blockchain)
  }

  const handleBackToOverview = () => {
    setViewMode('overview')
    setSelectedBlockchain(null)
    setSearchText('')
    setCategoryFilter(undefined)
    setEnabledFilter(undefined)
    loadOverviewData()
  }

  const handleToggle = async (rule: SystemRule) => {
    try {
      await rulesApi.updateSystemRule(rule.id, { is_enabled: !rule.is_enabled })
      setRules(prev =>
        prev.map(r =>
          r.id === rule.id ? { ...r, is_enabled: !r.is_enabled } : r
        )
      )
      message.success(`规则已${rule.is_enabled ? '禁用' : '启用'}`)
    } catch (error) {
      console.error('Failed to toggle rule:', error)
      message.error('操作失败')
    }
  }

  const handleBatchEnable = async (enable: boolean) => {
    const targetRules = filteredRules.filter(r => r.is_enabled !== enable)
    if (targetRules.length === 0) {
      message.info(`没有需要${enable ? '启用' : '禁用'}的规则`)
      return
    }

    try {
      await rulesApi.batchUpdateSystemRules({
        rule_ids: targetRules.map(r => r.id),
        is_enabled: enable,
      })
      if (selectedBlockchain) {
        await loadBlockchainRules(selectedBlockchain)
      }
      message.success(`已${enable ? '启用' : '禁用'} ${targetRules.length} 条规则`)
    } catch (error) {
      console.error('Failed to batch update:', error)
      message.error('批量操作失败')
    }
  }

  // 自定义规则操作
  const handleCreateCustomRule = () => {
    setEditingRule(null)
    form.resetFields()
    form.setFieldsValue({
      blockchain: selectedBlockchain || 'sui',
      match_all: false,
      is_enabled: true,
      severity_in: [],
      title_contains: '',
      description_contains: '',
    })
    setModalVisible(true)
  }

  const handleEditCustomRule = (rule: CustomExclusion) => {
    setEditingRule(rule)
    form.setFieldsValue({
      name: rule.name,
      description: rule.description,
      blockchain: rule.blockchain || undefined,
      is_enabled: rule.is_enabled,
      match_all: rule.match_config.match_all || false,
      title_contains: rule.match_config.title_contains?.join(', ') || '',
      description_contains: rule.match_config.description_contains?.join(', ') || '',
      function_pattern: rule.match_config.function_pattern || '',
      file_pattern: rule.match_config.file_pattern || '',
      severity_in: rule.match_config.severity_in || [],
    })
    setModalVisible(true)
  }

  const handleApplyExample = (example: typeof CUSTOM_RULE_EXAMPLES[0]) => {
    form.setFieldsValue({
      name: example.name,
      description: example.description,
      function_pattern: example.match_config.function_pattern || '',
      file_pattern: example.match_config.file_pattern || '',
      severity_in: example.match_config.severity_in || [],
      match_all: example.match_config.match_all || false,
    })
  }

  const handleDeleteCustomRule = async (id: string) => {
    try {
      await rulesApi.deleteCustomExclusion(id)
      setCustomRules(prev => prev.filter(r => r.id !== id))
      message.success('规则已删除')
    } catch (error) {
      console.error('Failed to delete rule:', error)
      message.error('删除失败')
    }
  }

  const handleToggleCustomRule = async (rule: CustomExclusion) => {
    try {
      await rulesApi.updateCustomExclusion(rule.id, { is_enabled: !rule.is_enabled })
      setCustomRules(prev =>
        prev.map(r =>
          r.id === rule.id ? { ...r, is_enabled: !r.is_enabled } : r
        )
      )
      message.success(`规则已${rule.is_enabled ? '禁用' : '启用'}`)
    } catch (error) {
      console.error('Failed to toggle rule:', error)
      message.error('操作失败')
    }
  }

  const handleSaveCustomRule = async () => {
    try {
      const values = await form.validateFields()

      const matchConfig: MatchConfig = {
        match_all: values.match_all,
      }

      if (values.title_contains?.trim()) {
        matchConfig.title_contains = values.title_contains.split(',').map((s: string) => s.trim()).filter(Boolean)
      }
      if (values.description_contains?.trim()) {
        matchConfig.description_contains = values.description_contains.split(',').map((s: string) => s.trim()).filter(Boolean)
      }
      if (values.function_pattern?.trim()) {
        matchConfig.function_pattern = values.function_pattern.trim()
      }
      if (values.file_pattern?.trim()) {
        matchConfig.file_pattern = values.file_pattern.trim()
      }
      if (values.severity_in?.length > 0) {
        matchConfig.severity_in = values.severity_in
      }

      const data = {
        name: values.name,
        description: values.description || null,
        blockchain: values.blockchain || null,
        match_config: matchConfig,
        is_enabled: values.is_enabled,
      }

      if (editingRule) {
        await rulesApi.updateCustomExclusion(editingRule.id, data)
        message.success('规则已更新')
      } else {
        await rulesApi.createCustomExclusion(data)
        message.success('规则已创建')
      }

      setModalVisible(false)
      if (selectedBlockchain) {
        loadBlockchainRules(selectedBlockchain)
      } else {
        loadOverviewData()
      }
    } catch (error) {
      console.error('Failed to save rule:', error)
      message.error('保存失败')
    }
  }

  // 过滤规则
  const filteredRules = rules.filter(rule => {
    if (searchText) {
      const search = searchText.toLowerCase()
      if (
        !rule.name.toLowerCase().includes(search) &&
        !rule.display_name.toLowerCase().includes(search) &&
        !(rule.description || '').toLowerCase().includes(search)
      ) {
        return false
      }
    }
    if (categoryFilter && rule.category !== categoryFilter) {
      return false
    }
    if (enabledFilter !== undefined && rule.is_enabled !== enabledFilter) {
      return false
    }
    return true
  })

  const filteredCustomRules = customRules.filter(rule => {
    if (selectedBlockchain && rule.blockchain !== selectedBlockchain) {
      return false
    }
    return true
  })

  const systemColumns = [
    {
      title: '状态',
      dataIndex: 'is_enabled',
      key: 'is_enabled',
      width: 80,
      render: (enabled: boolean, record: SystemRule) => (
        <Switch
          checked={enabled}
          onChange={() => handleToggle(record)}
          checkedChildren="启用"
          unCheckedChildren="禁用"
        />
      ),
    },
    {
      title: '规则名称',
      dataIndex: 'display_name',
      key: 'display_name',
      width: 200,
      render: (name: string, record: SystemRule) => (
        <Tooltip title={<><CodeOutlined /> 代码内置: {record.name}</>}>
          <span className="font-medium">{name}</span>
        </Tooltip>
      ),
    },
    {
      title: '分类',
      dataIndex: 'category',
      key: 'category',
      width: 100,
      render: (category: string) => {
        const config = CATEGORY_CONFIG[category] || { label: category, color: 'default' }
        return <Tag color={config.color}>{config.label}</Tag>
      },
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (desc: string | null) => (
        <Tooltip title={desc}>
          <span className="text-gray-600">{desc || '-'}</span>
        </Tooltip>
      ),
    },
    {
      title: '优先级',
      dataIndex: 'priority',
      key: 'priority',
      width: 80,
      sorter: (a: SystemRule, b: SystemRule) => a.priority - b.priority,
    },
    {
      title: '触发次数',
      dataIndex: 'trigger_count',
      key: 'trigger_count',
      width: 100,
      sorter: (a: SystemRule, b: SystemRule) => a.trigger_count - b.trigger_count,
      render: (count: number) => (
        <span className={count > 0 ? 'text-blue-600 font-medium' : 'text-gray-400'}>
          {count.toLocaleString()}
        </span>
      ),
    },
  ]

  const customColumns = [
    {
      title: '状态',
      dataIndex: 'is_enabled',
      key: 'is_enabled',
      width: 80,
      render: (enabled: boolean, record: CustomExclusion) => (
        <Switch
          checked={enabled}
          onChange={() => handleToggleCustomRule(record)}
          checkedChildren="启用"
          unCheckedChildren="禁用"
        />
      ),
    },
    {
      title: '规则名称',
      dataIndex: 'name',
      key: 'name',
      width: 160,
      render: (name: string) => (
        <span className="font-medium">{name}</span>
      ),
    },
    {
      title: '匹配条件',
      key: 'match_config',
      render: (_: unknown, record: CustomExclusion) => {
        const config = record.match_config
        const conditions: string[] = []
        if (config.title_contains?.length) {
          conditions.push(`标题含: ${config.title_contains.join(', ')}`)
        }
        if (config.description_contains?.length) {
          conditions.push(`描述含: ${config.description_contains.join(', ')}`)
        }
        if (config.function_pattern) {
          conditions.push(`函数: ${config.function_pattern}`)
        }
        if (config.file_pattern) {
          conditions.push(`文件: ${config.file_pattern}`)
        }
        if (config.severity_in?.length) {
          conditions.push(`严重性: ${config.severity_in.join(', ')}`)
        }
        return (
          <Tooltip title={conditions.join(' | ')}>
            <span className="text-gray-600">
              {conditions.length > 0 ? conditions.slice(0, 2).join('; ') + (conditions.length > 2 ? '...' : '') : '-'}
            </span>
          </Tooltip>
        )
      },
    },
    {
      title: '匹配模式',
      dataIndex: ['match_config', 'match_all'],
      key: 'match_all',
      width: 100,
      render: (matchAll: boolean) => (
        <Tag color={matchAll ? 'blue' : 'green'}>
          {matchAll ? '全部满足' : '任一满足'}
        </Tag>
      ),
    },
    {
      title: '触发次数',
      dataIndex: 'trigger_count',
      key: 'trigger_count',
      width: 80,
      render: (count: number) => (
        <span className={count > 0 ? 'text-blue-600 font-medium' : 'text-gray-400'}>
          {count}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 120,
      render: (_: unknown, record: CustomExclusion) => (
        <Space>
          <Button
            type="text"
            icon={<EditOutlined />}
            onClick={() => handleEditCustomRule(record)}
          />
          <Popconfirm
            title="确定删除此规则？"
            onConfirm={() => handleDeleteCustomRule(record.id)}
            okText="删除"
            cancelText="取消"
          >
            <Button type="text" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  // 概览视图 - 按链展示卡片
  const renderOverview = () => (
    <>
      <Alert
        message="规则按区块链分类管理，点击卡片进入查看和管理具体规则"
        type="info"
        showIcon
        icon={<InfoCircleOutlined />}
        className="mb-6"
      />

      <Row gutter={[24, 24]}>
        {blockchainInfos.map(info => (
          <Col xs={24} sm={12} lg={8} key={info.id}>
            <Card
              hoverable
              className="h-full"
              style={{ borderLeft: `4px solid ${info.color}` }}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-xl font-bold m-0">{info.name}</h3>
                  <p className="text-gray-500 text-sm mt-1">{info.description}</p>
                </div>
              </div>

              <Row gutter={16} className="mb-4">
                <Col span={8}>
                  <Statistic
                    title="系统规则"
                    value={info.ruleCount}
                    valueStyle={{ fontSize: '20px' }}
                  />
                </Col>
                <Col span={8}>
                  <Statistic
                    title="已启用"
                    value={info.enabledCount}
                    valueStyle={{ fontSize: '20px', color: '#52c41a' }}
                  />
                </Col>
                <Col span={8}>
                  <Statistic
                    title="自定义"
                    value={info.customCount}
                    valueStyle={{ fontSize: '20px', color: '#1890ff' }}
                  />
                </Col>
              </Row>

              <div className="flex gap-2">
                <Button
                  type="primary"
                  icon={<CodeOutlined />}
                  onClick={() => handleEnterBlockchain(info.id, 'system')}
                >
                  系统规则
                </Button>
                <Button
                  icon={<DatabaseOutlined />}
                  onClick={() => handleEnterBlockchain(info.id, 'custom')}
                >
                  自定义规则
                </Button>
              </div>
            </Card>
          </Col>
        ))}

      </Row>
    </>
  )

  // 系统规则详情视图
  const renderSystemRules = () => {
    const blockchainInfo = blockchainInfos.find(b => b.id === selectedBlockchain)
    const enabledCount = filteredRules.filter(r => r.is_enabled).length
    const disabledCount = filteredRules.filter(r => !r.is_enabled).length

    return (
      <>
        <Breadcrumb className="mb-4">
          <Breadcrumb.Item>
            <a onClick={handleBackToOverview}>规则管理</a>
          </Breadcrumb.Item>
          <Breadcrumb.Item>{blockchainInfo?.name || selectedBlockchain}</Breadcrumb.Item>
          <Breadcrumb.Item>系统规则</Breadcrumb.Item>
        </Breadcrumb>

        <div className="flex items-center gap-4 mb-6">
          <Button icon={<ArrowLeftOutlined />} onClick={handleBackToOverview}>
            返回
          </Button>
          <div>
            <h2 className="text-xl font-bold m-0">
              {blockchainInfo?.name} - 系统规则
            </h2>
            <p className="text-gray-500 text-sm m-0">
              共 {filteredRules.length} 条规则，{enabledCount} 条启用，{disabledCount} 条禁用
            </p>
          </div>
        </div>

        <Alert
          message="系统规则由 Python 代码实现，包含复杂的检测逻辑。您只能启用或禁用这些规则，无法修改其检测逻辑。"
          type="info"
          showIcon
          icon={<CodeOutlined />}
          className="mb-4"
        />

        {/* 过滤和操作 */}
        <Card className="mb-4">
          <div className="flex justify-between items-center">
            <Space>
              <Input
                placeholder="搜索规则名称或描述"
                prefix={<SearchOutlined />}
                value={searchText}
                onChange={e => setSearchText(e.target.value)}
                style={{ width: 200 }}
                allowClear
              />
              <Select
                placeholder="分类"
                value={categoryFilter}
                onChange={setCategoryFilter}
                style={{ width: 130 }}
                allowClear
              >
                {Object.entries(CATEGORY_CONFIG).map(([key, config]) => (
                  <Select.Option key={key} value={key}>
                    {config.label}
                  </Select.Option>
                ))}
              </Select>
              <Select
                placeholder="状态"
                value={enabledFilter}
                onChange={setEnabledFilter}
                style={{ width: 100 }}
                allowClear
              >
                <Select.Option value={true}>已启用</Select.Option>
                <Select.Option value={false}>已禁用</Select.Option>
              </Select>
            </Space>
            <Space>
              <Button onClick={() => handleBatchEnable(true)}>
                全部启用 ({disabledCount})
              </Button>
              <Button onClick={() => handleBatchEnable(false)} danger>
                全部禁用 ({enabledCount})
              </Button>
              <Button
                icon={<ReloadOutlined />}
                onClick={() => selectedBlockchain && loadBlockchainRules(selectedBlockchain)}
              >
                刷新
              </Button>
            </Space>
          </div>
        </Card>

        {/* 规则表格 */}
        <Card>
          <Table
            loading={loading}
            dataSource={filteredRules}
            columns={systemColumns}
            rowKey="id"
            pagination={{
              pageSize: 20,
              showSizeChanger: true,
              showTotal: total => `共 ${total} 条规则`,
            }}
            size="middle"
          />
        </Card>
      </>
    )
  }

  // 自定义规则详情视图
  const renderCustomRules = () => {
    const blockchainInfo = blockchainInfos.find(b => b.id === selectedBlockchain)

    return (
      <>
        <Breadcrumb className="mb-4">
          <Breadcrumb.Item>
            <a onClick={handleBackToOverview}>规则管理</a>
          </Breadcrumb.Item>
          <Breadcrumb.Item>{blockchainInfo?.name || selectedBlockchain}</Breadcrumb.Item>
          <Breadcrumb.Item>自定义规则</Breadcrumb.Item>
        </Breadcrumb>

        <div className="flex items-center gap-4 mb-6">
          <Button icon={<ArrowLeftOutlined />} onClick={handleBackToOverview}>
            返回
          </Button>
          <div>
            <h2 className="text-xl font-bold m-0">
              {blockchainInfo?.name} - 自定义规则
            </h2>
            <p className="text-gray-500 text-sm m-0">
              共 {filteredCustomRules.length} 条自定义规则
            </p>
          </div>
        </div>

        <Alert
          message="自定义规则使用模式匹配来排除误报。您可以根据漏洞标题、描述、函数名、文件路径、严重性等条件创建排除规则。"
          type="info"
          showIcon
          icon={<DatabaseOutlined />}
          className="mb-4"
        />

        <Card className="mb-4">
          <div className="flex justify-between items-center">
            <span className="text-gray-500">
              共 {filteredCustomRules.length} 条自定义规则
            </span>
            <Space>
              <Button
                type="primary"
                icon={<PlusOutlined />}
                onClick={handleCreateCustomRule}
              >
                新建规则
              </Button>
              <Button
                icon={<ReloadOutlined />}
                onClick={() => selectedBlockchain && loadBlockchainRules(selectedBlockchain)}
              >
                刷新
              </Button>
            </Space>
          </div>
        </Card>

        <Card>
          <Table
            loading={loading}
            dataSource={filteredCustomRules}
            columns={customColumns}
            rowKey="id"
            pagination={{
              pageSize: 20,
              showSizeChanger: true,
              showTotal: total => `共 ${total} 条规则`,
            }}
            size="middle"
            locale={{
              emptyText: (
                <div className="py-8 text-center text-gray-400">
                  <DatabaseOutlined className="text-4xl mb-2" />
                  <p>暂无自定义规则</p>
                  <Button
                    type="link"
                    onClick={handleCreateCustomRule}
                  >
                    创建第一条规则
                  </Button>
                </div>
              ),
            }}
          />
        </Card>
      </>
    )
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">规则管理</h1>

      {viewMode === 'overview' && renderOverview()}
      {viewMode === 'blockchain-system' && renderSystemRules()}
      {viewMode === 'blockchain-custom' && renderCustomRules()}

      {/* 创建/编辑自定义规则 Modal */}
      <Modal
        title={editingRule ? '编辑自定义规则' : '新建自定义规则'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        onOk={handleSaveCustomRule}
        okText="保存"
        cancelText="取消"
        width={650}
      >
        <Form form={form} layout="vertical" className="mt-4">
          {/* 示例模板 */}
          {!editingRule && (
            <div className="bg-blue-50 p-3 rounded mb-4">
              <span className="text-gray-600 mr-2">快速使用模板:</span>
              {CUSTOM_RULE_EXAMPLES.map((example, idx) => (
                <Button
                  key={idx}
                  size="small"
                  type="link"
                  onClick={() => handleApplyExample(example)}
                >
                  {example.name}
                </Button>
              ))}
            </div>
          )}

          <Row gutter={16}>
            <Col span={24}>
              <Form.Item
                name="name"
                label="规则名称"
                rules={[{ required: true, message: '请输入规则名称' }]}
              >
                <Input placeholder="例如：排除测试代码漏洞" />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} placeholder="规则用途说明" />
          </Form.Item>

          <Form.Item name="blockchain" hidden>
            <Input />
          </Form.Item>

          <div className="bg-gray-50 p-4 rounded mb-4">
            <h4 className="font-medium mb-3">匹配条件</h4>

            <Form.Item
              name="title_contains"
              label="标题包含 (逗号分隔)"
              tooltip="漏洞标题包含任意一个关键词时匹配"
            >
              <Input placeholder="例如：test, mock, example" />
            </Form.Item>

            <Form.Item
              name="description_contains"
              label="描述包含 (逗号分隔)"
              tooltip="漏洞描述包含任意一个关键词时匹配"
            >
              <Input placeholder="例如：helper, utility" />
            </Form.Item>

            <Form.Item
              name="function_pattern"
              label="函数名正则"
              tooltip="匹配函数名的正则表达式"
            >
              <Input placeholder="例如：^test_|_mock$" />
            </Form.Item>

            <Form.Item
              name="file_pattern"
              label="文件路径正则"
              tooltip="匹配文件路径的正则表达式"
            >
              <Input placeholder="例如：tests/.*|\.test\.move$" />
            </Form.Item>

            <Form.Item
              name="severity_in"
              label="严重性范围"
              tooltip="只匹配指定严重性的漏洞"
            >
              <Checkbox.Group options={SEVERITY_OPTIONS} />
            </Form.Item>

            <Form.Item
              name="match_all"
              valuePropName="checked"
              tooltip="开启后需要所有条件都满足才排除，否则任一条件满足即排除"
            >
              <Checkbox>需要全部条件满足 (AND 模式)</Checkbox>
            </Form.Item>
          </div>

          <Form.Item name="is_enabled" valuePropName="checked">
            <Checkbox>启用此规则</Checkbox>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
