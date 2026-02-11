import { useEffect, useState } from 'react'
import {
  Card,
  Descriptions,
  Table,
  Tag,
  Button,
  Spin,
  Select,
  Row,
  Col,
  Statistic,
  Drawer,
  Typography,
  Space,
  Empty,
} from 'antd'
import {
  BugOutlined,
  DownloadOutlined,
} from '@ant-design/icons'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { reportApi } from '../services/api'
import type { Report, Finding, Severity, FindingStatus } from '../types'
import { formatDateTime } from '../utils/time'

const { Paragraph, Text } = Typography

// 严重性配置
const SEVERITY_CONFIG: Record<Severity, { color: string; label: string; bgClass: string }> = {
  CRITICAL: { color: '#ff4d4f', label: '危急', bgClass: 'severity-critical' },
  HIGH: { color: '#ff7a45', label: '高危', bgClass: 'severity-high' },
  MEDIUM: { color: '#ffc53d', label: '中危', bgClass: 'severity-medium' },
  LOW: { color: '#73d13d', label: '低危', bgClass: 'severity-low' },
  ADVISORY: { color: '#1890ff', label: '建议', bgClass: 'severity-advisory' },
}

// 状态配置
const STATUS_CONFIG: Record<FindingStatus, { color: string; label: string }> = {
  open: { color: 'default', label: '待处理' },
  confirmed: { color: 'error', label: '已确认' },
  rejected: { color: 'success', label: '已驳回' },
  fixed: { color: 'processing', label: '已修复' },
}

interface ReportOverviewProps {
  reportId: string
}

export default function ReportOverview({ reportId }: ReportOverviewProps) {
  const [loading, setLoading] = useState(true)
  const [report, setReport] = useState<Report | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [drawerVisible, setDrawerVisible] = useState(false)
  const [severityFilter, setSeverityFilter] = useState<string | undefined>()

  useEffect(() => {
    if (reportId) {
      loadReport()
    }
  }, [reportId])

  useEffect(() => {
    if (reportId) {
      loadFindings()
    }
  }, [reportId, severityFilter])

  const loadReport = async () => {
    try {
      setLoading(true)
      const data = await reportApi.get(reportId)
      setReport(data)
    } catch (error) {
      console.error('Failed to load report:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadFindings = async () => {
    try {
      const res = await reportApi.getFindings(reportId, {
        severity: severityFilter,
        limit: 100,
      })
      setFindings(res.items)
    } catch (error) {
      console.error('Failed to load findings:', error)
    }
  }

  const handleExport = async (format: 'markdown' | 'json') => {
    try {
      const content = await reportApi.export(reportId, format)
      const blob = new Blob([content as string], {
        type: format === 'json' ? 'application/json' : 'text/markdown',
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report_${reportId}.${format === 'json' ? 'json' : 'md'}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Export failed:', error)
    }
  }

  const showFindingDetail = (finding: Finding) => {
    setSelectedFinding(finding)
    setDrawerVisible(true)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spin size="large" />
      </div>
    )
  }

  if (!report) {
    return <Empty description="报告不存在" />
  }

  // 严重性分布数据
  const severityData = [
    { name: '危急', value: report.critical_count, color: SEVERITY_CONFIG.CRITICAL.color },
    { name: '高危', value: report.high_count, color: SEVERITY_CONFIG.HIGH.color },
    { name: '中危', value: report.medium_count, color: SEVERITY_CONFIG.MEDIUM.color },
    { name: '低危', value: report.low_count, color: SEVERITY_CONFIG.LOW.color },
    { name: '建议', value: report.advisory_count, color: SEVERITY_CONFIG.ADVISORY.color },
  ].filter((d) => d.value > 0)

  const columns = [
    {
      title: '严重性',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      sorter: (a: Finding, b: Finding) => {
        const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, ADVISORY: 4 }
        return (order[a.severity] ?? 99) - (order[b.severity] ?? 99)
      },
      defaultSortOrder: 'ascend' as const,
      render: (severity: string) => {
        const config = SEVERITY_CONFIG[severity as Severity]
        return config
          ? <Tag className={config.bgClass}>{config.label}</Tag>
          : <Tag>{severity || '未知'}</Tag>
      },
    },
    {
      title: '漏洞标题',
      dataIndex: 'title',
      key: 'title',
      render: (title: string, record: Finding) => (
        <Button type="link" onClick={() => showFindingDetail(record)}>
          {title}
        </Button>
      ),
    },
    {
      title: '位置',
      dataIndex: 'location',
      key: 'location',
      width: 200,
      render: (location?: { file: string; line_start: number }) =>
        location ? (
          <code className="text-xs bg-gray-100 px-2 py-1 rounded">
            {location.file}:{location.line_start}
          </code>
        ) : (
          '-'
        ),
    },
  ]

  return (
    <div className="space-y-4">
      {/* 概览 */}
      <Row gutter={16}>
        <Col span={16}>
          <Card
            title="报告概览"
            extra={
              <Button size="small" icon={<DownloadOutlined />} onClick={() => handleExport('markdown')}>
                导出 Markdown
              </Button>
            }
          >
            <Descriptions column={2}>
              <Descriptions.Item label="报告 ID">{report.id}</Descriptions.Item>
              <Descriptions.Item label="总漏洞数">{report.total_findings}</Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDateTime(report.created_at)}
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="严重性分布">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={150}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={30}
                    outerRadius={60}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-green-500 py-8">
                <CheckCircleOutlined className="text-4xl mb-2" />
                <div>无漏洞</div>
              </div>
            )}
          </Card>
        </Col>
      </Row>

      {/* 统计卡片 */}
      <Row gutter={16}>
        {Object.entries(SEVERITY_CONFIG).map(([key, config]) => {
          const count =
            key === 'CRITICAL'
              ? report.critical_count
              : key === 'HIGH'
              ? report.high_count
              : key === 'MEDIUM'
              ? report.medium_count
              : key === 'LOW'
              ? report.low_count
              : report.advisory_count
          return (
            <Col span={4} key={key}>
              <Card size="small">
                <Statistic
                  title={config.label}
                  value={count}
                  valueStyle={{ color: config.color }}
                  prefix={<BugOutlined />}
                />
              </Card>
            </Col>
          )
        })}
      </Row>

      {/* 漏洞列表 */}
      <Card
        title="漏洞列表"
        extra={
          <Select
            allowClear
            placeholder="严重性筛选"
            style={{ width: 120 }}
            value={severityFilter}
            onChange={setSeverityFilter}
            options={Object.entries(SEVERITY_CONFIG).map(([key, config]) => ({
              value: key,
              label: config.label,
            }))}
          />
        }
      >
        <Table
          dataSource={findings}
          columns={columns}
          rowKey={(record, index) => record.id || `finding-${index}`}
          pagination={{ pageSize: 10 }}
          locale={{ emptyText: '无匹配漏洞' }}
        />
      </Card>

      {/* 漏洞详情抽屉 */}
      <Drawer
        title={
          selectedFinding && (
            <Space>
              <Tag className={SEVERITY_CONFIG[selectedFinding.severity as Severity]?.bgClass || ''}>
                {SEVERITY_CONFIG[selectedFinding.severity as Severity]?.label || selectedFinding.severity}
              </Tag>
              {selectedFinding.title}
            </Space>
          )
        }
        placement="right"
        width={600}
        open={drawerVisible}
        onClose={() => setDrawerVisible(false)}
      >
        {selectedFinding && (
          <div className="space-y-4">
            <div>
              <Text type="secondary">状态</Text>
              <div>
                <Tag color={STATUS_CONFIG[selectedFinding.status as FindingStatus]?.color || 'default'}>
                  {STATUS_CONFIG[selectedFinding.status as FindingStatus]?.label || selectedFinding.status}
                </Tag>
              </div>
            </div>

            {selectedFinding.location && (
              <div>
                <Text type="secondary">位置</Text>
                <div>
                  <code className="bg-gray-100 px-2 py-1 rounded">
                    {selectedFinding.location.file}:{selectedFinding.location.line_start}-
                    {selectedFinding.location.line_end}
                  </code>
                </div>
              </div>
            )}

            {selectedFinding.category && (
              <div>
                <Text type="secondary">分类</Text>
                <div>
                  <Tag>{selectedFinding.category}</Tag>
                </div>
              </div>
            )}

            <div>
              <Text type="secondary">描述</Text>
              <Paragraph>{selectedFinding.description}</Paragraph>
            </div>

            {selectedFinding.proof && (
              <div>
                <Text type="secondary">漏洞证明</Text>
                <Paragraph className="bg-red-50 p-2 rounded border-l-4 border-red-400">
                  {selectedFinding.proof}
                </Paragraph>
              </div>
            )}

            {selectedFinding.attack_scenario && (
              <div>
                <Text type="secondary">攻击场景</Text>
                <pre className="bg-orange-50 p-3 rounded text-sm whitespace-pre-wrap">
                  {selectedFinding.attack_scenario}
                </pre>
              </div>
            )}

            {selectedFinding.code_snippet && (
              <div>
                <Text type="secondary">漏洞代码</Text>
                <pre className="code-block mt-2">{selectedFinding.code_snippet}</pre>
              </div>
            )}

            {selectedFinding.recommendation && (
              <div>
                <Text type="secondary">修复建议</Text>
                <pre className="bg-green-50 p-3 rounded text-sm whitespace-pre-wrap border-l-4 border-green-400">
                  {selectedFinding.recommendation}
                </pre>
              </div>
            )}

            {selectedFinding.review_notes && selectedFinding.review_notes.length > 0 && (
              <div>
                <Text type="secondary">Review 备注</Text>
                {selectedFinding.review_notes.map((note, index) => (
                  <Card size="small" key={index} className="mt-2">
                    <div className="text-gray-500 text-xs mb-1">
                      {formatDateTime(note.created_at)}
                    </div>
                    {note.content}
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  )
}

function CheckCircleOutlined(props: React.HTMLAttributes<HTMLSpanElement>) {
  return <span {...props}>✓</span>
}
