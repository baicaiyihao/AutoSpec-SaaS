import { useEffect, useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Card, Progress, Steps, Button, Tag, Spin, message, Alert, Descriptions } from 'antd'
import {
  ArrowLeftOutlined,
  StopOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  LoadingOutlined,
  FileSearchOutlined,
} from '@ant-design/icons'
import { auditApi } from '../services/api'
import type { Audit } from '../types'
import { formatDateTime } from '../utils/time'

// 阶段配置
const PHASES = [
  { key: 0, title: '初始化', description: '系统初始化' },
  { key: 1, title: '代码分析', description: '分析合约结构' },
  { key: 2, title: '漏洞扫描', description: '模式匹配扫描' },
  { key: 3, title: 'Agent 验证', description: '多 Agent 验证' },
  { key: 4, title: '利用链验证', description: 'WhiteHat 验证' },
  { key: 5, title: '生成报告', description: '生成审计报告' },
]

export default function AuditExecution() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [audit, setAudit] = useState<Audit | null>(null)
  const [loading, setLoading] = useState(true)
  const [logs, setLogs] = useState<string[]>([])
  const [progress, setProgress] = useState({ phase: 0, percent: 0, message: '' })
  const [isRunning, setIsRunning] = useState(false)
  const logContainerRef = useRef<HTMLDivElement>(null)
  const pollIntervalRef = useRef<number | null>(null)
  const logOffsetRef = useRef<number>(0)  // 使用 ref 跟踪 offset，避免闭包问题

  useEffect(() => {
    if (id) {
      loadAudit()
    }
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
      }
    }
  }, [id])

  useEffect(() => {
    // 自动滚动到日志底部
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs])

  const loadAudit = async () => {
    try {
      setLoading(true)
      const auditData = await auditApi.get(id!)
      setAudit(auditData)

      // 重置状态
      setLogs([])
      logOffsetRef.current = 0

      if (auditData.status === 'running' || auditData.status === 'pending') {
        setIsRunning(true)
        startPolling()
      } else {
        setIsRunning(false)
        // 加载最后的进度和日志
        if (auditData.progress) {
          setProgress({
            phase: auditData.progress.current_phase,
            percent: auditData.progress.progress_percent,
            message: auditData.progress.phase_name,
          })
          const historicalLogs = auditData.progress.messages || []
          setLogs(historicalLogs)
          logOffsetRef.current = historicalLogs.length  // 设置正确的 offset
        }
      }
    } catch (error: any) {
      if (error.response?.status === 404) {
        message.warning('审计任务不存在')
        navigate('/projects')
      } else {
        message.error('加载审计任务失败')
      }
    } finally {
      setLoading(false)
    }
  }

  const startPolling = () => {
    // 立即获取一次
    fetchProgressAndLogs()

    // 设置轮询（3秒一次，后端每2秒更新日志）
    pollIntervalRef.current = window.setInterval(() => {
      fetchProgressAndLogs()
    }, 3000)
  }

  const fetchProgressAndLogs = async () => {
    try {
      const [progressData, logsData] = await Promise.all([
        auditApi.getProgress(id!),
        auditApi.getLogs(id!, logOffsetRef.current),  // 使用 ref 跟踪 offset
      ])

      setProgress({
        phase: progressData.phase,
        percent: progressData.percent,
        message: progressData.message,
      })

      // 处理日志：后端只保留最后500条
      // 当 offset >= total 说明日志被截断了，需要重置获取最新日志
      if (logOffsetRef.current >= logsData.total && logsData.total > 0 && progressData.is_running) {
        // 日志已滚动，用最新日志替换（从 offset=0 重新获取）
        const freshLogs = await auditApi.getLogs(id!, 0)
        setLogs(freshLogs.logs)
        logOffsetRef.current = freshLogs.logs.length
      } else if (logsData.logs.length > 0) {
        // 正常追加新日志
        setLogs((prev) => [...prev, ...logsData.logs])
        logOffsetRef.current += logsData.logs.length
      }

      if (!progressData.is_running) {
        // 任务结束，停止轮询
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current)
          pollIntervalRef.current = null
        }
        setIsRunning(false)
        // 刷新审计状态
        const auditData = await auditApi.get(id!)
        setAudit(auditData)
        // 更新最终进度和日志（直接用完整日志替换，不追加）
        if (auditData.progress) {
          setProgress({
            phase: auditData.progress.current_phase,
            percent: auditData.progress.progress_percent,
            message: auditData.progress.phase_name,
          })
          const finalLogs = auditData.progress.messages || []
          setLogs(finalLogs)
          logOffsetRef.current = finalLogs.length
        }
      }
    } catch (error: any) {
      console.error('Failed to fetch progress:', error)
      // 如果审计任务不存在（404），停止轮询并导航到项目列表
      if (error.response?.status === 404) {
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current)
        }
        setIsRunning(false)
        message.warning('审计任务已被删除或不存在')
        navigate('/projects')
      }
    }
  }

  const handleCancel = async () => {
    try {
      await auditApi.cancel(id!)
      message.success('审计任务已取消')
      // 先停止轮询
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
      setIsRunning(false)
      // 直接获取最新状态，不启动轮询
      const auditData = await auditApi.get(id!)
      setAudit(auditData)
      if (auditData.progress) {
        setProgress({
          phase: auditData.progress.current_phase,
          percent: auditData.progress.progress_percent,
          message: auditData.progress.phase_name,
        })
        const cancelledLogs = auditData.progress.messages || []
        setLogs(cancelledLogs)
        logOffsetRef.current = cancelledLogs.length
      }
    } catch (error) {
      message.error('取消任务失败')
    }
  }

  const handleViewReport = () => {
    if (audit?.report_id) {
      navigate(`/reports/${audit.report_id}`)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spin size="large" />
      </div>
    )
  }

  if (!audit) {
    return <Alert type="error" message="审计任务不存在" showIcon />
  }

  // 状态颜色和图标
  const getStatusDisplay = () => {
    switch (audit.status) {
      case 'pending':
        return { color: 'default', text: '等待中', icon: <LoadingOutlined /> }
      case 'running':
        return { color: 'processing', text: '运行中', icon: <LoadingOutlined spin /> }
      case 'completed':
        return { color: 'success', text: '已完成', icon: <CheckCircleOutlined /> }
      case 'failed':
        return { color: 'error', text: '失败', icon: <CloseCircleOutlined /> }
      case 'cancelled':
        return { color: 'warning', text: '已取消', icon: <StopOutlined /> }
      default:
        return { color: 'default', text: audit.status, icon: null }
    }
  }

  const statusDisplay = getStatusDisplay()

  return (
    <div className="space-y-4">
      {/* 头部 */}
      <div className="flex items-center justify-between">
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/projects')}>
          返回项目列表
        </Button>
        <div className="space-x-2">
          {(audit.status === 'pending' || audit.status === 'running') && (
            <Button danger icon={<StopOutlined />} onClick={handleCancel}>
              取消审计
            </Button>
          )}
          {audit.status === 'completed' && audit.report_id && (
            <Button type="primary" icon={<FileSearchOutlined />} onClick={handleViewReport}>
              查看报告
            </Button>
          )}
        </div>
      </div>

      {/* 审计信息 */}
      <Card>
        <Descriptions column={3}>
          <Descriptions.Item label="项目">{audit.project_name}</Descriptions.Item>
          <Descriptions.Item label="状态">
            <Tag color={statusDisplay.color} icon={statusDisplay.icon}>
              {statusDisplay.text}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="创建时间">
            {formatDateTime(audit.created_at)}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      {/* 错误信息 */}
      {audit.status === 'failed' && audit.error_message && (
        <Alert type="error" message="审计失败" description={audit.error_message} showIcon />
      )}

      {/* 进度 */}
      <Card title="审计进度">
        <div className="mb-6">
          <Progress
            percent={progress.percent}
            status={isRunning ? 'active' : audit.status === 'completed' ? 'success' : 'exception'}
            strokeColor={{
              '0%': '#108ee9',
              '100%': '#87d068',
            }}
            format={(percent) => `${percent?.toFixed(0)}%`}
          />
          <div className="text-center text-gray-500 mt-2">{progress.message}</div>
        </div>

        <Steps
          current={progress.phase}
          status={isRunning ? 'process' : audit.status === 'completed' ? 'finish' : 'error'}
          items={PHASES.map((phase) => ({
            title: phase.title,
            description: phase.description,
          }))}
        />
      </Card>

      {/* 实时日志 */}
      <Card
        title={
          <div className="flex items-center">
            <span>执行日志</span>
            {isRunning && <Tag color="processing" className="ml-2">实时更新</Tag>}
          </div>
        }
        extra={
          <span className="text-gray-400 text-sm">
            {logs.length} 条日志
            {isRunning && <LoadingOutlined className="ml-2" spin />}
          </span>
        }
      >
        <div
          ref={logContainerRef}
          className="log-container"
          style={{ maxHeight: '500px', overflowY: 'auto' }}
        >
          {logs.length === 0 ? (
            <div className="text-gray-400 text-center py-8">
              {isRunning ? '等待日志...' : '暂无日志'}
            </div>
          ) : (
            logs.map((log, index) => (
              <div
                key={`${index}-${log.slice(0, 20)}`}
                className="py-0.5 leading-relaxed hover:bg-gray-800 px-2 -mx-2 rounded"
              >
                {log}
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  )
}
