import { useEffect, useState, useRef } from 'react'
import { Card, Table, Button, Tag, Space, Popconfirm, message, Progress } from 'antd'
import {
  DeleteOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
  StopOutlined,
  ReloadOutlined,
  PlayCircleOutlined,
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { auditApi, reportApi } from '../services/api'
import type { Audit, Report, Severity } from '../types'
import { formatDateTime } from '../utils/time'

// 状态配置
const STATUS_CONFIG: Record<string, { color: string; text: string; icon: React.ReactNode }> = {
  pending: { color: 'default', text: '等待中', icon: <LoadingOutlined /> },
  running: { color: 'processing', text: '运行中', icon: <LoadingOutlined spin /> },
  completed: { color: 'success', text: '已完成', icon: <CheckCircleOutlined /> },
  failed: { color: 'error', text: '失败', icon: <CloseCircleOutlined /> },
  cancelled: { color: 'warning', text: '已取消', icon: <StopOutlined /> },
}

const SEVERITY_CONFIG: Record<Severity, { color: string; label: string }> = {
  CRITICAL: { color: '#ff4d4f', label: '危急' },
  HIGH: { color: '#ff7a45', label: '高危' },
  MEDIUM: { color: '#ffc53d', label: '中危' },
  LOW: { color: '#73d13d', label: '低危' },
  ADVISORY: { color: '#1890ff', label: '建议' },
}

interface AuditWithReport extends Audit {
  report?: Report
}

export default function AuditList() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [audits, setAudits] = useState<AuditWithReport[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    loadAudits()
    intervalRef.current = setInterval(() => {
      loadAudits(true)
    }, 5000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [page, pageSize])

  const loadAudits = async (silent = false) => {
    try {
      if (!silent) setLoading(true)
      const res = await auditApi.list({
        skip: (page - 1) * pageSize,
        limit: pageSize,
      })

      // For completed audits with report_id, fetch report data
      const auditsWithReport: AuditWithReport[] = await Promise.all(
        res.items.map(async (audit) => {
          if (audit.status === 'completed' && audit.report_id) {
            try {
              const report = await reportApi.get(audit.report_id)
              return { ...audit, report }
            } catch {
              return audit
            }
          }
          return audit
        })
      )

      setAudits(auditsWithReport)
      setTotal(res.total)
    } catch (error) {
      if (!silent) message.error('加载审计列表失败')
    } finally {
      if (!silent) setLoading(false)
    }
  }

  const handleCancel = async (auditId: string) => {
    try {
      await auditApi.cancel(auditId)
      message.success('审计任务已取消')
      loadAudits()
    } catch (error) {
      message.error('取消任务失败')
    }
  }

  const handleBatchDelete = async () => {
    try {
      await Promise.all(selectedRowKeys.map((id) => auditApi.delete(id)))
      message.success(`已删除 ${selectedRowKeys.length} 个审计任务`)
      setSelectedRowKeys([])
      loadAudits()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const handleDownloadLogs = async (auditId: string) => {
    try {
      const res = await auditApi.getLogs(auditId, 0)
      const content = res.logs.join('\n')
      const blob = new Blob([content], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit_${auditId}_logs.txt`
      a.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      message.error('日志下载失败')
    }
  }

  const columns = [
    {
      title: '项目名称',
      dataIndex: 'project_name',
      key: 'project_name',
      render: (name: string, record: AuditWithReport) => (
        <Button type="link" className="px-0" onClick={() => navigate(`/audits/${record.id}`)}>
          {name}
        </Button>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => {
        const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending
        return <Tag color={cfg.color} icon={cfg.icon}>{cfg.text}</Tag>
      },
    },
    {
      title: '漏洞分布',
      key: 'severity_distribution',
      width: 300,
      render: (_: unknown, record: AuditWithReport) => {
        // Running/Pending: show progress bar
        if (record.status === 'running' || record.status === 'pending') {
          return (
            <Progress
              percent={record.progress?.progress_percent || 0}
              size="small"
              status="active"
              format={(p) => `${p?.toFixed(0)}%`}
            />
          )
        }
        // Completed with report: show severity tags
        if (record.status === 'completed' && record.report) {
          const r = record.report
          return (
            <div className="flex items-center space-x-1">
              {r.critical_count > 0 && (
                <Tag color={SEVERITY_CONFIG.CRITICAL.color}>{r.critical_count} 危急</Tag>
              )}
              {r.high_count > 0 && (
                <Tag color={SEVERITY_CONFIG.HIGH.color}>{r.high_count} 高危</Tag>
              )}
              {r.medium_count > 0 && (
                <Tag color={SEVERITY_CONFIG.MEDIUM.color}>{r.medium_count} 中危</Tag>
              )}
              {r.low_count > 0 && (
                <Tag color={SEVERITY_CONFIG.LOW.color}>{r.low_count} 低危</Tag>
              )}
              {r.total_findings === 0 && <Tag color="success">无漏洞</Tag>}
            </div>
          )
        }
        // Failed: show progress at failure point
        if (record.status === 'failed') {
          return (
            <Progress
              percent={record.progress?.progress_percent || 0}
              size="small"
              status="exception"
            />
          )
        }
        return <span className="text-gray-400">-</span>
      },
    },
    {
      title: '总计',
      key: 'total_findings',
      width: 70,
      render: (_: unknown, record: AuditWithReport) => {
        if (record.status === 'completed' && record.report) {
          const count = record.report.total_findings
          return (
            <span className={count > 0 ? 'text-red-500 font-medium' : 'text-green-500'}>
              {count}
            </span>
          )
        }
        return <span className="text-gray-400">-</span>
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date: string) => formatDateTime(date),
    },
    {
      title: '操作',
      key: 'action',
      width: 250,
      render: (_: unknown, record: AuditWithReport) => {
        // Running/Pending
        if (record.status === 'running' || record.status === 'pending') {
          return (
            <Space split={<span className="text-gray-300">|</span>}>
              <Button
                type="link"
                size="small"
                className="px-0"
                onClick={() => navigate(`/audits/${record.id}`)}
              >
                查看进度
              </Button>
              <Popconfirm
                title="确定取消此审计任务？"
                onConfirm={() => handleCancel(record.id)}
                okText="确定"
                cancelText="取消"
              >
                <Button type="link" size="small" className="px-0" danger>
                  取消
                </Button>
              </Popconfirm>
            </Space>
          )
        }
        // Completed with report
        if (record.status === 'completed' && record.report_id) {
          return (
            <Space split={<span className="text-gray-300">|</span>}>
              <Button
                type="link"
                size="small"
                className="px-0"
                onClick={() => navigate(`/reports/${record.report_id}`)}
              >
                查看结果
              </Button>
              <Button
                type="link"
                size="small"
                className="px-0"
                onClick={() => navigate(`/reports/${record.report_id}`, { state: { tab: 'audit' } })}
              >
                漏洞审计
              </Button>
              <Button
                type="link"
                size="small"
                className="px-0"
                onClick={() => handleDownloadLogs(record.id)}
              >
                下载日志
              </Button>
            </Space>
          )
        }
        // Failed/Cancelled/Completed without report
        return (
          <Button
            type="link"
            size="small"
            className="px-0"
            onClick={() => navigate(`/audits/${record.id}`)}
          >
            查看详情
          </Button>
        )
      },
    },
  ]

  const runningCount = audits.filter((a) => a.status === 'running' || a.status === 'pending').length

  return (
    <Card
      title={
        <div className="flex items-center">
          <span>审计管理</span>
          {runningCount > 0 && (
            <Tag color="processing" className="ml-2">
              {runningCount} 个运行中
            </Tag>
          )}
        </div>
      }
      extra={
        <Space>
          <Popconfirm
            title="确认删除"
            description={`确认删除选中的 ${selectedRowKeys.length} 个审计任务？关联的报告也将被删除。`}
            onConfirm={handleBatchDelete}
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            disabled={selectedRowKeys.length === 0}
          >
            <Button
              danger
              icon={<DeleteOutlined />}
              disabled={selectedRowKeys.length === 0}
            >
              删除{selectedRowKeys.length > 0 ? ` (${selectedRowKeys.length})` : ''}
            </Button>
          </Popconfirm>
          <Button icon={<ReloadOutlined />} onClick={() => loadAudits()}>
            刷新
          </Button>
          <Button type="primary" icon={<PlayCircleOutlined />} onClick={() => navigate('/projects')}>
            新建审计
          </Button>
        </Space>
      }
    >
      <Table
        loading={loading}
        dataSource={audits}
        columns={columns}
        rowKey="id"
        rowSelection={{
          selectedRowKeys,
          onChange: (keys) => setSelectedRowKeys(keys as string[]),
        }}
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 个审计`,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
        rowClassName={(record) => {
          if (record.status === 'running') return 'bg-blue-50'
          if (record.status === 'failed') return 'bg-red-50'
          return ''
        }}
      />
    </Card>
  )
}
