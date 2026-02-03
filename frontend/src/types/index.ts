/**
 * AutoSpec 前端类型定义
 */

// 项目
export interface Project {
  id: string
  name: string
  description?: string
  blockchain?: string  // 所属链 (sui)
  source_path: string
  file_count: number
  created_at: string
  updated_at: string
  last_audit_id?: string
  last_audit_status?: AuditStatus
}

// 审计状态
export type AuditStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

// 审计进度
export interface AuditProgress {
  current_phase: number
  phase_name: string
  progress_percent: number
  messages: string[]
}

// 审计任务
export interface Audit {
  id: string
  project_id: string
  project_name: string
  status: AuditStatus
  config: Record<string, unknown>
  progress?: AuditProgress
  started_at?: string
  completed_at?: string
  error_message?: string
  report_id?: string
  created_at: string
}

// 漏洞严重性
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'ADVISORY'

// 漏洞状态
export type FindingStatus = 'open' | 'confirmed' | 'rejected' | 'fixed'

// 漏洞
export interface Finding {
  id: string
  title: string
  severity: Severity
  status: FindingStatus
  category?: string
  description: string
  location?: {
    file: string
    line_start: number
    line_end: number
  }
  recommendation?: string
  code_snippet?: string
  proof?: string           // 漏洞证明
  attack_scenario?: string // 攻击场景
  review_notes?: Array<{
    content: string
    created_at: string
  }>
}

// 报告
export interface Report {
  id: string
  audit_id: string
  findings: Finding[]
  summary: {
    total_findings: number
    by_severity: Record<Severity, number>
    by_status: Record<FindingStatus, number>
  }
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  advisory_count: number
  report_path?: string
  created_at: string
  updated_at: string
}

// Review 会话
export interface ReviewSession {
  id: string
  report_id: string
  focused_finding_id?: string
  is_active: boolean
  messages: ReviewMessage[]
  actions: ReviewAction[]
  created_at: string
  updated_at: string
}

// Review 消息
export interface ReviewMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  metadata?: Record<string, unknown>
  created_at: string
}

// Review 操作
export interface ReviewAction {
  id: string
  finding_id: string
  action_type: 'confirm' | 'reject' | 'downgrade' | 'upgrade' | 'add_note'
  from_value?: string
  to_value?: string
  reason?: string
  ai_analysis?: string
  created_at: string
}

// API 响应
export interface ListResponse<T> {
  total: number
  items: T[]
}

// 审计日志响应
export interface AuditLogsResponse {
  audit_id: string
  logs: string[]
  total: number
  is_running: boolean
}
