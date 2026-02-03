import { useEffect, useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Card,
  List,
  Tag,
  Button,
  Input,
  Space,
  Spin,
  message,
  Modal,
  Select,
  Empty,
  Typography,
  Divider,
} from 'antd'
import {
  ArrowLeftOutlined,
  SendOutlined,
  CheckOutlined,
  CloseOutlined,
  ArrowDownOutlined,
  ArrowUpOutlined,
  MessageOutlined,
} from '@ant-design/icons'
import { reportApi, reviewApi } from '../services/api'
import type { Report, Finding, ReviewSession,  Severity, FindingStatus } from '../types'

const { TextArea } = Input
const { Text } = Typography

// 严重性配置
const SEVERITY_CONFIG: Record<Severity, { color: string; label: string; bgClass: string }> = {
  CRITICAL: { color: '#ff4d4f', label: '危急', bgClass: 'severity-critical' },
  HIGH: { color: '#ff7a45', label: '高危', bgClass: 'severity-high' },
  MEDIUM: { color: '#ffc53d', label: '中危', bgClass: 'severity-medium' },
  LOW: { color: '#73d13d', label: '低危', bgClass: 'severity-low' },
  ADVISORY: { color: '#1890ff', label: '建议', bgClass: 'severity-advisory' },
}

const STATUS_CONFIG: Record<FindingStatus, { color: string; label: string }> = {
  open: { color: 'default', label: '待处理' },
  confirmed: { color: 'error', label: '已确认' },
  rejected: { color: 'success', label: '已驳回' },
  fixed: { color: 'processing', label: '已修复' },
}

export default function Review() {
  const { reportId } = useParams<{ reportId: string }>()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [report, setReport] = useState<Report | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [session, setSession] = useState<ReviewSession | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [chatInput, setChatInput] = useState('')
  const [sending, setSending] = useState(false)
  const [actionModalVisible, setActionModalVisible] = useState(false)
  const [actionType, setActionType] = useState<'confirm' | 'reject' | 'downgrade' | 'upgrade'>('confirm')
  const [actionReason, setActionReason] = useState('')
  const [newSeverity, setNewSeverity] = useState<Severity>('MEDIUM')
  const chatContainerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (reportId) {
      loadData()
    }
  }, [reportId])

  useEffect(() => {
    // 自动滚动到聊天底部
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight
    }
  }, [session?.messages])

  const loadData = async () => {
    try {
      setLoading(true)
      const [reportData, findingsData] = await Promise.all([
        reportApi.get(reportId!),
        reportApi.getFindings(reportId!, { limit: 100 }),
      ])
      setReport(reportData)
      setFindings(findingsData.items)

      // 创建或获取 Review 会话
      const sessionData = await reviewApi.createSession({ report_id: reportId! })
      setSession(sessionData)
    } catch (error) {
      message.error('加载数据失败')
    } finally {
      setLoading(false)
    }
  }

  const handleSelectFinding = async (finding: Finding) => {
    setSelectedFinding(finding)
    if (session) {
      try {
        await reviewApi.focusFinding(session.id, finding.id)
        // 刷新会话
        const updatedSession = await reviewApi.getSession(session.id)
        setSession(updatedSession)
      } catch (error) {
        message.error('聚焦漏洞失败')
      }
    }
  }

  const handleSendMessage = async () => {
    if (!chatInput.trim() || !session) return

    try {
      setSending(true)
      await reviewApi.chat(session.id, chatInput)
      setChatInput('')

      // 刷新会话获取新消息
      const updatedSession = await reviewApi.getSession(session.id)
      setSession(updatedSession)
    } catch (error) {
      message.error('发送消息失败')
    } finally {
      setSending(false)
    }
  }

  const handleAction = async () => {
    if (!session || !selectedFinding) return

    try {
      await reviewApi.applyAction(session.id, {
        finding_id: selectedFinding.id,
        action_type: actionType,
        new_severity: ['downgrade', 'upgrade'].includes(actionType) ? newSeverity : undefined,
        reason: actionReason,
      })

      message.success('操作成功')
      setActionModalVisible(false)
      setActionReason('')

      // 刷新数据
      const [findingsData, updatedSession] = await Promise.all([
        reportApi.getFindings(reportId!, { limit: 100 }),
        reviewApi.getSession(session.id),
      ])
      setFindings(findingsData.items)
      setSession(updatedSession)

      // 更新选中的漏洞
      const updated = findingsData.items.find((f) => f.id === selectedFinding.id)
      if (updated) {
        setSelectedFinding(updated)
      }
    } catch (error) {
      message.error('操作失败')
    }
  }

  const openActionModal = (type: 'confirm' | 'reject' | 'downgrade' | 'upgrade') => {
    setActionType(type)
    setActionModalVisible(true)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spin size="large" />
      </div>
    )
  }

  if (!report || !session) {
    return <Empty description="数据加载失败" />
  }

  return (
    <div className="space-y-4">
      {/* 头部 */}
      <div className="flex items-center justify-between">
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(`/reports/${reportId}`)}>
          返回报告
        </Button>
        <Text type="secondary">Review 会话 ID: {session.id.slice(0, 8)}...</Text>
      </div>

      {/* 主体区域 */}
      <div className="grid grid-cols-4 gap-4" style={{ height: 'calc(100vh - 200px)' }}>
        {/* 漏洞列表 */}
        <Card title="漏洞列表" className="col-span-1 overflow-auto" size="small">
          <List
            dataSource={findings}
            renderItem={(finding) => (
              <List.Item
                className={`cursor-pointer hover:bg-gray-50 transition-colors ${
                  selectedFinding?.id === finding.id ? 'bg-blue-50' : ''
                }`}
                onClick={() => handleSelectFinding(finding)}
              >
                <div className="w-full">
                  <div className="flex items-center justify-between">
                    <Tag className={SEVERITY_CONFIG[finding.severity].bgClass} style={{ margin: 0 }}>
                      {SEVERITY_CONFIG[finding.severity].label}
                    </Tag>
                    <Tag color={STATUS_CONFIG[finding.status].color} style={{ margin: 0 }}>
                      {STATUS_CONFIG[finding.status].label}
                    </Tag>
                  </div>
                  <div className="text-sm mt-1 truncate">{finding.title}</div>
                </div>
              </List.Item>
            )}
          />
        </Card>

        {/* 漏洞详情 */}
        <Card title="漏洞详情" className="col-span-1 overflow-auto" size="small">
          {selectedFinding ? (
            <div className="space-y-3">
              <div>
                <Text type="secondary" className="text-xs">标题</Text>
                <div className="font-medium">{selectedFinding.title}</div>
              </div>
              <div>
                <Text type="secondary" className="text-xs">严重性</Text>
                <div>
                  <Tag className={SEVERITY_CONFIG[selectedFinding.severity].bgClass}>
                    {SEVERITY_CONFIG[selectedFinding.severity].label}
                  </Tag>
                </div>
              </div>
              <div>
                <Text type="secondary" className="text-xs">状态</Text>
                <div>
                  <Tag color={STATUS_CONFIG[selectedFinding.status].color}>
                    {STATUS_CONFIG[selectedFinding.status].label}
                  </Tag>
                </div>
              </div>
              <div>
                <Text type="secondary" className="text-xs">描述</Text>
                <div className="text-sm">{selectedFinding.description}</div>
              </div>
              {selectedFinding.code_snippet && (
                <div>
                  <Text type="secondary" className="text-xs">代码片段</Text>
                  <pre className="code-block text-xs mt-1 max-h-32 overflow-auto">
                    {selectedFinding.code_snippet}
                  </pre>
                </div>
              )}

              <Divider />

              {/* 操作按钮 */}
              <div className="space-y-2">
                <Button
                  block
                  type="primary"
                  danger
                  icon={<CheckOutlined />}
                  onClick={() => openActionModal('confirm')}
                  disabled={selectedFinding.status === 'confirmed'}
                >
                  确认漏洞
                </Button>
                <Button
                  block
                  icon={<CloseOutlined />}
                  onClick={() => openActionModal('reject')}
                  disabled={selectedFinding.status === 'rejected'}
                >
                  驳回（误报）
                </Button>
                <Button
                  block
                  icon={<ArrowDownOutlined />}
                  onClick={() => openActionModal('downgrade')}
                >
                  降级严重性
                </Button>
                <Button
                  block
                  icon={<ArrowUpOutlined />}
                  onClick={() => openActionModal('upgrade')}
                >
                  升级严重性
                </Button>
              </div>
            </div>
          ) : (
            <Empty description="请选择一个漏洞" />
          )}
        </Card>

        {/* 聊天区域 */}
        <Card
          title={
            <Space>
              <MessageOutlined />
              AI 助手对话
            </Space>
          }
          className="col-span-2 flex flex-col"
          size="small"
          bodyStyle={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
        >
          {/* 消息列表 */}
          <div
            ref={chatContainerRef}
            className="flex-1 overflow-auto mb-4 space-y-3"
            style={{ maxHeight: 'calc(100vh - 380px)' }}
          >
            {session.messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[80%] rounded-lg px-4 py-2 ${
                    msg.role === 'user'
                      ? 'bg-blue-500 text-white'
                      : msg.role === 'system'
                      ? 'bg-gray-100 text-gray-600 text-sm'
                      : 'bg-gray-200 text-gray-800'
                  }`}
                >
                  {msg.role === 'system' && (
                    <Text type="secondary" className="text-xs block mb-1">系统</Text>
                  )}
                  <div className="whitespace-pre-wrap">{msg.content}</div>
                </div>
              </div>
            ))}
            {session.messages.length === 0 && (
              <div className="text-center text-gray-400 py-8">
                选择一个漏洞，然后向 AI 助手提问
              </div>
            )}
          </div>

          {/* 输入区域 */}
          <div className="flex space-x-2">
            <TextArea
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              placeholder="输入问题，例如：这个漏洞是否为误报？"
              autoSize={{ minRows: 2, maxRows: 4 }}
              onPressEnter={(e) => {
                if (!e.shiftKey) {
                  e.preventDefault()
                  handleSendMessage()
                }
              }}
            />
            <Button
              type="primary"
              icon={<SendOutlined />}
              onClick={handleSendMessage}
              loading={sending}
              disabled={!chatInput.trim()}
            >
              发送
            </Button>
          </div>
        </Card>
      </div>

      {/* 操作确认弹窗 */}
      <Modal
        title={
          actionType === 'confirm'
            ? '确认漏洞'
            : actionType === 'reject'
            ? '驳回漏洞'
            : actionType === 'downgrade'
            ? '降级严重性'
            : '升级严重性'
        }
        open={actionModalVisible}
        onOk={handleAction}
        onCancel={() => {
          setActionModalVisible(false)
          setActionReason('')
        }}
        okText="确认"
        cancelText="取消"
      >
        {['downgrade', 'upgrade'].includes(actionType) && (
          <div className="mb-4">
            <Text type="secondary">新严重性级别</Text>
            <Select
              className="w-full mt-1"
              value={newSeverity}
              onChange={setNewSeverity}
              options={Object.entries(SEVERITY_CONFIG).map(([key, config]) => ({
                value: key,
                label: config.label,
              }))}
            />
          </div>
        )}
        <div>
          <Text type="secondary">操作理由（可选）</Text>
          <TextArea
            className="mt-1"
            value={actionReason}
            onChange={(e) => setActionReason(e.target.value)}
            placeholder="请输入操作理由..."
            rows={3}
          />
        </div>
      </Modal>
    </div>
  )
}
