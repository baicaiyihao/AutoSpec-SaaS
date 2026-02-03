import { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Tag, Button, Spin, Progress, Empty, Table, Space, Typography } from 'antd'
import {
  BugOutlined,
  ProjectOutlined,
  FileSearchOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
  StopOutlined,
  RightOutlined,
  ThunderboltOutlined,
  WalletOutlined,
} from '@ant-design/icons'
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts'
import { useNavigate } from 'react-router-dom'
import { projectApi, auditApi, reportApi, api } from '../services/api'
import type { Project, Audit, Report, Severity } from '../types'
import { formatDateTime } from '../utils/time'
import { useAuth } from '../contexts/AuthContext'
import { useCurrentAccount } from '@mysten/dapp-kit'

const { Text } = Typography

// 严重性颜色
const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ff4d4f',
  HIGH: '#ff7a45',
  MEDIUM: '#ffc53d',
  LOW: '#73d13d',
  ADVISORY: '#1890ff',
}

// 状态配置
const STATUS_CONFIG: Record<string, { color: string; text: string; icon: React.ReactNode }> = {
  pending: { color: 'default', text: '等待中', icon: <LoadingOutlined /> },
  running: { color: 'processing', text: '运行中', icon: <LoadingOutlined spin /> },
  completed: { color: 'success', text: '已完成', icon: <CheckCircleOutlined /> },
  failed: { color: 'error', text: '失败', icon: <CloseCircleOutlined /> },
  cancelled: { color: 'warning', text: '已取消', icon: <StopOutlined /> },
}

interface TokenPurchase {
  id: string
  transaction_digest: string
  sui_amount: number
  usd_amount: number
  token_amount: number
  status: string
  created_at: string
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const currentAccount = useCurrentAccount()
  const [loading, setLoading] = useState(true)
  const [, setProjects] = useState<Project[]>([])
  const [recentAudits, setRecentAudits] = useState<Audit[]>([])
  const [recentPurchases, setRecentPurchases] = useState<TokenPurchase[]>([])
  const [stats, setStats] = useState({
    totalProjects: 0,
    totalAudits: 0,
    totalFindings: 0,
    severityDistribution: [] as Array<{ name: string; value: number; color: string }>,
  })

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      setLoading(true)
      const promises = [
        projectApi.list({ limit: 100 }),
        auditApi.list({ limit: 5 }),
        reportApi.list({ limit: 100 }),
      ]

      // 加载购买记录
      if (user?.wallet_address) {
        promises.push(api.get('/tokens/purchase-history', { params: { limit: 5 } }))
      }

      const results = await Promise.all(promises)
      const [projectsRes, auditsRes, reportsRes, purchasesRes] = results

      setProjects(projectsRes.items)
      setRecentAudits(auditsRes.items)

      if (purchasesRes) {
        setRecentPurchases(purchasesRes.data.purchases || [])
      }

      // 计算统计数据
      const severityCounts: Record<string, number> = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        ADVISORY: 0,
      }

      let totalFindings = 0
      reportsRes.items.forEach((report: Report) => {
        totalFindings += report.total_findings
        severityCounts.CRITICAL += report.critical_count
        severityCounts.HIGH += report.high_count
        severityCounts.MEDIUM += report.medium_count
        severityCounts.LOW += report.low_count
        severityCounts.ADVISORY += report.advisory_count
      })

      setStats({
        totalProjects: projectsRes.total,
        totalAudits: auditsRes.total,
        totalFindings,
        severityDistribution: Object.entries(severityCounts).map(([name, value]) => ({
          name,
          value,
          color: SEVERITY_COLORS[name as Severity],
        })),
      })
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spin size="large" />
      </div>
    )
  }

  // 获取运行中的任务数量
  const runningCount = recentAudits.filter(a => a.status === 'running' || a.status === 'pending').length

  return (
    <div className="space-y-6">
      {/* KPI 卡片 - 第一行 */}
      <Row gutter={16}>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable onClick={() => navigate('/token-purchase')} className="cursor-pointer">
            <Statistic
              title="LLM Tokens"
              value={user?.token_balance || 0}
              prefix={<ThunderboltOutlined className="text-yellow-500" />}
              formatter={(value) => (value as number).toLocaleString()}
              suffix={
                <Button type="link" size="small" onClick={(e) => { e.stopPropagation(); navigate('/token-purchase') }}>
                  充值
                </Button>
              }
            />
            {currentAccount && (
              <div className="mt-2">
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  <WalletOutlined /> {currentAccount.address.slice(0, 6)}...{currentAccount.address.slice(-4)}
                </Text>
              </div>
            )}
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable onClick={() => navigate('/projects')} className="cursor-pointer">
            <Statistic
              title="项目总数"
              value={stats.totalProjects}
              prefix={<ProjectOutlined className="text-blue-500" />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable className="cursor-pointer">
            <Statistic
              title="审计任务"
              value={stats.totalAudits}
              prefix={<FileSearchOutlined className="text-green-500" />}
              suffix={runningCount > 0 ? <Tag color="processing" className="ml-2">{runningCount} 运行中</Tag> : null}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="高危漏洞"
              value={(stats.severityDistribution.find((s) => s.name === 'CRITICAL')?.value || 0) +
                     (stats.severityDistribution.find((s) => s.name === 'HIGH')?.value || 0)}
              valueStyle={{ color: '#ff4d4f' }}
              prefix={<WarningOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* 主要内容区域 */}
      <Row gutter={16}>
        {/* 最近审计任务 */}
        <Col span={14}>
          <Card
            title="最近审计任务"
            extra={
              <Button type="link" onClick={() => navigate('/audits')}>
                查看全部 <RightOutlined />
              </Button>
            }
          >
            {recentAudits.length === 0 ? (
              <Empty
                description="暂无审计任务"
                image={Empty.PRESENTED_IMAGE_SIMPLE}
              >
                <Button type="primary" onClick={() => navigate('/projects')}>
                  创建第一个审计
                </Button>
              </Empty>
            ) : (
              <div className="space-y-3">
                {recentAudits.map((audit) => {
                  const statusCfg = STATUS_CONFIG[audit.status] || STATUS_CONFIG.pending
                  return (
                    <div
                      key={audit.id}
                      className="p-4 border rounded-lg hover:border-blue-400 hover:shadow-sm transition-all cursor-pointer"
                      onClick={() => {
                        if (audit.status === 'running' || audit.status === 'pending') {
                          navigate(`/audits/${audit.id}`)
                        } else if (audit.report_id) {
                          navigate(`/reports/${audit.report_id}`)
                        } else {
                          navigate(`/audits/${audit.id}`)
                        }
                      }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium text-gray-800">{audit.project_name}</span>
                        <Tag color={statusCfg.color} icon={statusCfg.icon}>
                          {statusCfg.text}
                        </Tag>
                      </div>
                      {(audit.status === 'running' || audit.status === 'pending') && audit.progress && (
                        <Progress
                          percent={audit.progress.progress_percent}
                          size="small"
                          status="active"
                          format={() => audit.progress?.phase_name || ''}
                        />
                      )}
                      <div className="text-xs text-gray-400 mt-1">
                        {formatDateTime(audit.created_at)}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </Card>
        </Col>

        {/* 漏洞分布 */}
        <Col span={10}>
          <Card title="漏洞严重性分布">
            {stats.totalFindings === 0 ? (
              <Empty
                description="暂无漏洞数据"
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                className="py-8"
              />
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={stats.severityDistribution.filter((s) => s.value > 0)}
                    cx="50%"
                    cy="50%"
                    labelLine={true}
                    label={({ name, value }) => `${name}: ${value}`}
                    outerRadius={90}
                    dataKey="value"
                  >
                    {stats.severityDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            )}
          </Card>
        </Col>
      </Row>

      {/* 漏洞统计柱状图 - 只在有数据时显示 */}
      {stats.totalFindings > 0 && (
        <Card title="漏洞统计">
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={stats.severityDistribution}>
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="value" name="数量">
                {stats.severityDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}

      {/* Token 购买记录 */}
      {user?.wallet_address && recentPurchases.length > 0 && (
        <Card
          title="最近购买记录"
          extra={
            <Button type="link" onClick={() => navigate('/token-purchase')}>
              查看全部 <RightOutlined />
            </Button>
          }
        >
          <Table
            dataSource={recentPurchases}
            rowKey="id"
            pagination={false}
            size="small"
            columns={[
              {
                title: '交易哈希',
                dataIndex: 'transaction_digest',
                key: 'transaction_digest',
                render: (digest: string) => (
                  <Text code copyable={{ text: digest }}>
                    {digest.slice(0, 12)}...{digest.slice(-6)}
                  </Text>
                ),
              },
              {
                title: 'LLM Tokens',
                dataIndex: 'token_amount',
                key: 'token_amount',
                render: (amount: number) => (
                  <Space>
                    <ThunderboltOutlined style={{ color: '#faad14' }} />
                    <Text strong>{amount.toLocaleString()}</Text>
                  </Space>
                ),
              },
              {
                title: '支付金额',
                dataIndex: 'sui_amount',
                key: 'sui_amount',
                render: (amount: number, record: TokenPurchase) => (
                  <Space direction="vertical" size={0}>
                    <Text>{(amount / 1_000_000_000).toFixed(4)} SUI</Text>
                    <Text type="secondary" style={{ fontSize: '12px' }}>
                      ≈ ${(record.usd_amount / 100).toFixed(2)}
                    </Text>
                  </Space>
                ),
              },
              {
                title: '状态',
                dataIndex: 'status',
                key: 'status',
                render: (status: string) => {
                  const statusMap: Record<string, { color: string; text: string }> = {
                    success: { color: 'success', text: '成功' },
                    pending: { color: 'processing', text: '处理中' },
                    failed: { color: 'error', text: '失败' },
                  }
                  const cfg = statusMap[status] || { color: 'default', text: status }
                  return <Tag color={cfg.color}>{cfg.text}</Tag>
                },
              },
              {
                title: '时间',
                dataIndex: 'created_at',
                key: 'created_at',
                render: (time: string) => formatDateTime(time),
              },
            ]}
          />
        </Card>
      )}
    </div>
  )
}
