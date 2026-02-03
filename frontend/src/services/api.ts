/**
 * API 服务
 */
import axios from 'axios'
import type {
  Project,
  Audit,
  Report,
  Finding,
  ReviewSession,
  ListResponse,
  AuditLogsResponse,
} from '../types'
import type {
  LoginRequest,
  RegisterRequest,
  TokenResponse,
  UserInfo,
  ApiKeysStatus,
  ApiKeysUpdate,
  AuditConfig,
  SystemSetting,
  PresetTemplate,
  ServerApiKeyStatus,
  PresetCreateRequest,
  PresetUpdateRequest,
  PaymentModeInfo,
  PaymentModeUpdateRequest,
} from '../types/auth'
import { getStoredToken, getStoredRefreshToken, updateStoredToken } from '../contexts/AuthContext'

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
})

// 🔥 标记：是否正在刷新 token
let isRefreshing = false
let failedQueue: Array<{ resolve: (value?: any) => void; reject: (reason?: any) => void }> = []

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error)
    } else {
      prom.resolve(token)
    }
  })
  failedQueue = []
}

// 请求拦截器：添加 Bearer token
api.interceptors.request.use((config) => {
  const token = getStoredToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器：401 自动刷新 token 或跳转登录页
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config
    const message = error.response?.data?.detail || error.message
    console.error('API Error:', message)

    // 🔥 401 错误处理：尝试刷新 token
    if (error.response?.status === 401 && !originalRequest._retry) {
      // 如果是 refresh 端点本身失败，直接跳转登录
      if (originalRequest.url?.includes('/auth/refresh')) {
        localStorage.removeItem('autospec_token')
        localStorage.removeItem('autospec_refresh_token')
        localStorage.removeItem('autospec_user')
        if (window.location.pathname !== '/login') {
          window.location.href = '/login'
        }
        return Promise.reject(error)
      }

      // 如果已经在刷新中，等待刷新完成
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        })
          .then((token) => {
            originalRequest.headers.Authorization = `Bearer ${token}`
            return api(originalRequest)
          })
          .catch((err) => Promise.reject(err))
      }

      originalRequest._retry = true
      isRefreshing = true

      const refreshToken = getStoredRefreshToken()
      if (!refreshToken) {
        // 没有 refresh token，直接跳转登录
        localStorage.removeItem('autospec_token')
        localStorage.removeItem('autospec_user')
        if (window.location.pathname !== '/login') {
          window.location.href = '/login'
        }
        return Promise.reject(error)
      }

      try {
        // 调用 refresh API
        const res = await api.post<TokenResponse>('/auth/refresh', { refresh_token: refreshToken })
        const newAccessToken = res.data.access_token

        // 更新 token
        updateStoredToken(newAccessToken)
        processQueue(null, newAccessToken)

        // 重试原请求
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`
        return api(originalRequest)
      } catch (refreshError) {
        // 刷新失败，清除登录状态
        processQueue(refreshError, null)
        localStorage.removeItem('autospec_token')
        localStorage.removeItem('autospec_refresh_token')
        localStorage.removeItem('autospec_user')
        if (window.location.pathname !== '/login') {
          window.location.href = '/login'
        }
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }

    return Promise.reject(error)
  }
)

// ============ Auth API ============

export const authApi = {
  login: async (data: LoginRequest) => {
    const res = await api.post<TokenResponse>('/auth/login', data)
    return res.data
  },

  register: async (data: RegisterRequest) => {
    const res = await api.post<TokenResponse>('/auth/register', data)
    return res.data
  },

  me: async () => {
    const res = await api.get<UserInfo>('/auth/me')
    return res.data
  },

  getCaptchaConfig: async () => {
    const res = await api.get<{ enabled: boolean }>('/auth/captcha-config')
    return res.data
  },

  // 🔥 刷新 access token
  refresh: async (refreshToken: string) => {
    const res = await api.post<TokenResponse>('/auth/refresh', { refresh_token: refreshToken })
    return res.data
  },

  // 🔥 退出登录
  logout: async (refreshToken: string) => {
    const res = await api.post('/auth/logout', { refresh_token: refreshToken })
    return res.data
  },

  // 🔥 钱包登录 - 获取挑战
  getWalletChallenge: async (walletAddress: string) => {
    const res = await api.post<{ message: string; nonce: string; expires_at: number }>('/auth/wallet/challenge', { wallet_address: walletAddress })
    return res.data
  },

  // 🔥 钱包登录 - 验证签名
  verifyWalletLogin: async (data: { wallet_address: string; signature: string; message: string; public_key: string }) => {
    const res = await api.post<TokenResponse>('/auth/wallet/verify', data)
    return res.data
  },

  // 🔥 获取当前用户信息（刷新用户数据）
  getCurrentUser: async () => {
    const res = await api.get<UserInfo>('/auth/me')
    return res.data
  },
}

// ============ Users API (Admin + Self) ============

export const usersApi = {
  // Admin: 用户列表
  list: async () => {
    const res = await api.get<{ users: UserInfo[]; total: number }>('/users')
    return res.data
  },

  // Admin: 修改角色
  updateRole: async (userId: string, role: string) => {
    const res = await api.post(`/users/${userId}/role`, { role })
    return res.data
  },

  // Admin: 启用/禁用
  updateStatus: async (userId: string, is_active: boolean) => {
    const res = await api.post(`/users/${userId}/status`, { is_active })
    return res.data
  },

  // Admin: 允许/禁止使用共享 API Keys
  updateSharedApiKeys: async (userId: string, allow_shared_api_keys: boolean) => {
    const res = await api.post(`/users/${userId}/shared-api-keys`, { allow_shared_api_keys })
    return res.data
  },

  // Admin: 删除用户
  delete: async (userId: string) => {
    const res = await api.post(`/users/${userId}/delete`)
    return res.data
  },

  // User: 获取自己的共享 API Keys 权限
  getSharedApiKeysPermission: async () => {
    const res = await api.get<{ allow_shared_api_keys: boolean }>('/users/me/shared-api-keys-permission')
    return res.data
  },

  // User: 获取 API Key 状态
  getApiKeys: async () => {
    const res = await api.get<ApiKeysStatus>('/users/me/api-keys')
    return res.data
  },

  // User: 更新 API Keys
  updateApiKeys: async (data: ApiKeysUpdate) => {
    const res = await api.post('/users/me/api-keys', data)
    return res.data
  },

  // User: 修改密码
  changePassword: async (data: { old_password: string; new_password: string }) => {
    const res = await api.post('/users/me/password', data)
    return res.data
  },

  // User: 获取审计配置
  getAuditConfig: async () => {
    const res = await api.get<AuditConfig>('/users/me/audit-config')
    return res.data
  },

  // User: 更新审计配置
  updateAuditConfig: async (data: Partial<AuditConfig>) => {
    const res = await api.post('/users/me/audit-config', data)
    return res.data
  },

  // ========== Token 额度管理 ==========

  // User: 获取自己的 Token 额度
  getMyTokenQuota: async () => {
    const res = await api.get<{
      token_quota: number | null
      tokens_used: number
      remaining: number | null
      is_unlimited: boolean
      usage_percent: number | null
    }>('/users/me/token-quota')
    return res.data
  },

  // User: 获取自己的 Token 使用记录
  getMyTokenUsage: async (params?: { limit?: number; offset?: number }) => {
    const res = await api.get<{
      records: Array<{
        id: string
        project_id: string | null
        project_name: string | null
        audit_id: string | null
        prompt_tokens: number
        completion_tokens: number
        total_tokens: number
        agent_breakdown: Record<string, { prompt: number; completion: number; total: number; calls: number }>
        audit_status: string | null
        created_at: string
      }>
      total_count: number
      total_tokens: number
    }>('/users/me/token-usage', { params })
    return res.data
  },

  // Admin: 获取指定用户的 Token 额度
  getUserTokenQuota: async (userId: string) => {
    const res = await api.get<{
      token_quota: number | null
      tokens_used: number
      remaining: number | null
      is_unlimited: boolean
      usage_percent: number | null
    }>(`/users/${userId}/token-quota`)
    return res.data
  },

  // Admin: 设置用户 Token 额度
  setUserTokenQuota: async (userId: string, tokenQuota: number | null) => {
    const res = await api.post(`/users/${userId}/token-quota`, { token_quota: tokenQuota })
    return res.data
  },

  // Admin: 重置用户 Token 使用量
  resetUserTokenUsage: async (userId: string) => {
    const res = await api.post(`/users/${userId}/reset-token-usage`)
    return res.data
  },

  // Admin: 获取指定用户的 Token 使用记录
  getUserTokenUsage: async (userId: string, params?: { limit?: number; offset?: number }) => {
    const res = await api.get<{
      records: Array<{
        id: string
        project_id: string | null
        project_name: string | null
        audit_id: string | null
        prompt_tokens: number
        completion_tokens: number
        total_tokens: number
        agent_breakdown: Record<string, { prompt: number; completion: number; total: number; calls: number }>
        audit_status: string | null
        created_at: string
      }>
      total_count: number
      total_tokens: number
    }>(`/users/${userId}/token-usage`, { params })
    return res.data
  },

  // Admin: 获取所有用户 Token 统计
  getAllUsersTokenStats: async () => {
    const res = await api.get<{
      users: Array<{
        user_id: string
        username: string
        role: string
        token_quota: number | null
        tokens_used: number
        remaining: number | null
        is_unlimited: boolean
        audit_count: number
      }>
      system_total_tokens: number
    }>('/users/admin/token-stats')
    return res.data
  },

  // User: Token 使用量趋势
  getMyTokenTrend: async (params?: { time_range?: 'day' | 'week' | 'month'; limit?: number }) => {
    const res = await api.get<{
      data: Array<{ date: string; tokens: number; audits: number }>
    }>('/users/me/token-stats/trend', { params })
    return res.data.data
  },

  // User: 按项目统计
  getMyTokenByProject: async (params?: { limit?: number }) => {
    const res = await api.get<{
      data: Array<{ project_name: string; tokens: number; audits: number }>
    }>('/users/me/token-stats/by-project', { params })
    return res.data.data
  },

  // User: 按 Agent 统计
  getMyTokenByAgent: async () => {
    const res = await api.get<{
      data: Record<string, number>
    }>('/users/me/token-stats/by-agent')
    return res.data.data
  },

  // User: 获取 Token 购买记录
  getTokenPurchaseHistory: async (params?: { page?: number; limit?: number }) => {
    const res = await api.get('/tokens/purchase-history', { params })
    return res
  },

  // User: 解绑钱包
  unbindWallet: async () => {
    const res = await api.post('/auth/wallet/unbind')
    return res.data
  },

  // ========== 付费模式管理 ==========

  // User: 获取付费模式
  getPaymentMode: async () => {
    const res = await api.get<PaymentModeInfo>('/users/me/payment-mode')
    return res.data
  },

  // User: 更新付费模式
  updatePaymentMode: async (data: PaymentModeUpdateRequest) => {
    const res = await api.post('/users/me/payment-mode', data)
    return res.data
  },
}

// ============ Settings API (Admin) ============

export const settingsApi = {
  get: async () => {
    const res = await api.get<{ settings: SystemSetting[] }>('/settings')
    return res.data.settings
  },

  update: async (settings: Array<{ key: string; value: string }>) => {
    const res = await api.post('/settings', { settings })
    return res.data
  },

  getPresets: async () => {
    const res = await api.get<{ presets: Record<string, PresetTemplate> }>('/settings/presets')
    return res.data.presets
  },

  createPreset: async (data: PresetCreateRequest) => {
    const res = await api.post('/settings/presets', data)
    return res.data
  },

  updatePreset: async (key: string, data: PresetUpdateRequest) => {
    const res = await api.post(`/settings/presets/${key}`, data)
    return res.data
  },

  deletePreset: async (key: string) => {
    const res = await api.post(`/settings/presets/${key}/delete`)
    return res.data
  },

  getServerApiKeys: async () => {
    const res = await api.get<{ keys: ServerApiKeyStatus[] }>('/settings/api-keys')
    return res.data.keys
  },

  updateServerApiKeys: async (keys: Record<string, string>) => {
    const res = await api.post('/settings/api-keys', keys)
    return res.data
  },
}

// ============ 项目 API ============

export const projectApi = {
  // 获取项目列表
  list: async (params?: { skip?: number; limit?: number }) => {
    const res = await api.get<ListResponse<Project>>('/projects', { params })
    return res.data
  },

  // 获取项目详情
  get: async (id: string) => {
    const res = await api.get<Project>(`/projects/${id}`)
    return res.data
  },

  // 创建项目（通过路径）
  create: async (data: { name: string; description?: string; source_path: string; blockchain?: string }) => {
    const res = await api.post<Project>('/projects', data)
    return res.data
  },

  // 上传项目文件夹
  upload: async (formData: FormData, onProgress?: (progress: number) => void) => {
    const res = await api.post<Project>('/projects/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          onProgress(progressEvent.loaded / progressEvent.total)
        }
      },
    })
    return res.data
  },

  // 更新项目
  update: async (id: string, data: { name?: string; description?: string }) => {
    const res = await api.put<Project>(`/projects/${id}`, data)
    return res.data
  },

  // 删除项目
  delete: async (id: string) => {
    await api.delete(`/projects/${id}`)
  },

  // 获取项目文件列表
  getFiles: async (id: string) => {
    const res = await api.get<{ files: Array<{ path: string; name: string; size: number }> }>(
      `/projects/${id}/files`
    )
    return res.data.files
  },

  // 获取项目文件内容
  getFileContent: async (id: string, filePath: string) => {
    const res = await api.get<{ content: string }>(`/projects/${id}/files/${filePath}`)
    return res.data.content
  },

  // 重新导入项目（上传方式）
  reimport: async (id: string, formData: FormData, onProgress?: (progress: number) => void) => {
    const res = await api.post<Project>(`/projects/${id}/reimport`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          onProgress(progressEvent.loaded / progressEvent.total)
        }
      },
    })
    return res.data
  },

  // 重新导入项目（本地路径方式）
  reimportPath: async (id: string, source_path: string) => {
    const res = await api.post<Project>(`/projects/${id}/reimport-path`, { source_path })
    return res.data
  },
}

// ============ 审计 API ============

export const auditApi = {
  // 获取审计列表
  list: async (params?: { project_id?: string; status?: string; skip?: number; limit?: number }) => {
    const res = await api.get<ListResponse<Audit>>('/audits', { params })
    return res.data
  },

  // 获取审计详情
  get: async (id: string) => {
    const res = await api.get<Audit>(`/audits/${id}`)
    return res.data
  },

  // 创建审计任务
  create: async (data: { project_id: string; config?: Record<string, unknown> }) => {
    const res = await api.post<Audit>('/audits', data)
    return res.data
  },

  // 删除审计任务
  delete: async (id: string) => {
    await api.delete(`/audits/${id}`)
  },

  // 取消审计任务
  cancel: async (id: string) => {
    const res = await api.post<Audit>(`/audits/${id}/cancel`)
    return res.data
  },

  // 获取审计日志
  getLogs: async (id: string, offset = 0) => {
    const res = await api.get<AuditLogsResponse>(`/audits/${id}/logs`, { params: { offset } })
    return res.data
  },

  // 获取审计进度
  getProgress: async (id: string) => {
    const res = await api.get<{
      audit_id: string
      phase: number
      phase_name: string
      percent: number
      message: string
      is_running: boolean
    }>(`/audits/${id}/progress`)
    return res.data
  },
}

// ============ 报告 API ============

export const reportApi = {
  // 获取报告列表
  list: async (params?: { audit_id?: string; skip?: number; limit?: number }) => {
    const res = await api.get<ListResponse<Report>>('/reports', { params })
    return res.data
  },

  // 获取报告详情
  get: async (id: string) => {
    const res = await api.get<Report>(`/reports/${id}`)
    return res.data
  },

  // 删除报告
  delete: async (id: string) => {
    await api.delete(`/reports/${id}`)
  },

  // 获取报告漏洞列表
  getFindings: async (
    id: string,
    params?: { severity?: string; status?: string; skip?: number; limit?: number }
  ) => {
    const res = await api.get<ListResponse<Finding>>(`/reports/${id}/findings`, { params })
    return res.data
  },

  // 获取单个漏洞详情
  getFinding: async (reportId: string, findingId: string) => {
    const res = await api.get<Finding>(`/reports/${reportId}/findings/${findingId}`)
    return res.data
  },

  // 导出报告
  export: async (id: string, format: 'markdown' | 'json' | 'pdf' = 'markdown') => {
    const res = await api.get(`/reports/${id}/export`, {
      params: { format },
      responseType: format === 'pdf' ? 'blob' : 'text',
    })
    return res.data
  },

  // 手动添加漏洞
  addFinding: async (reportId: string, data: {
    title: string
    severity: string
    category?: string
    description: string
    location?: { file?: string; module?: string; function?: string }
    code_snippet?: string
    recommendation?: string
    proof?: string
    attack_scenario?: string
  }) => {
    const res = await api.post(`/reports/${reportId}/findings`, data)
    return res.data
  },
}

// ============ Review API ============

export const reviewApi = {
  // 创建 Review 会话
  createSession: async (data: { report_id: string; initial_finding_id?: string }) => {
    const res = await api.post<ReviewSession>('/review/sessions', data)
    return res.data
  },

  // 获取 Review 会话
  getSession: async (id: string) => {
    const res = await api.get<ReviewSession>(`/review/sessions/${id}`)
    return res.data
  },

  // 聚焦漏洞
  focusFinding: async (sessionId: string, findingId: string) => {
    const res = await api.post(`/review/sessions/${sessionId}/focus`, { finding_id: findingId })
    return res.data
  },

  // 发送聊天消息 (非流式，兜底用)
  chat: async (sessionId: string, message: string) => {
    const res = await api.post<{ message_id: string; content: string; suggested_actions?: string[] }>(
      `/review/sessions/${sessionId}/chat`,
      { message },
      { timeout: 120000 }
    )
    return res.data
  },

  // 流式聊天 - SSE 进度事件
  chatStream: (
    sessionId: string,
    message: string,
    onProgress: (event: { type: string; content: string; round?: number; total_rounds?: number }) => void,
    onComplete: (content: string) => void,
    onError: (error: string) => void,
    findingId?: string
  ) => {
    const controller = new AbortController()

    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    const token = getStoredToken()
    if (token) headers['Authorization'] = `Bearer ${token}`

    fetch(`/api/v1/review/sessions/${sessionId}/chat/stream`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ message, finding_id: findingId }),
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          onError(`请求失败: ${response.status}`)
          return
        }
        const reader = response.body?.getReader()
        if (!reader) {
          onError('无法读取响应流')
          return
        }

        const decoder = new TextDecoder()
        let buffer = ''

        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split('\n')
          buffer = lines.pop() || ''

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6).trim()
              if (data === '[DONE]') {
                return
              }
              try {
                const event = JSON.parse(data)
                if (event.type === 'response') {
                  onComplete(event.content)
                } else if (event.type === 'error') {
                  onError(event.content)
                } else if (event.type === 'message_id') {
                  // 忽略 message_id 事件
                } else {
                  onProgress(event)
                }
              } catch {
                // 忽略解析错误
              }
            }
          }
        }
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          onError(`网络错误: ${err.message}`)
        }
      })

    return controller
  },

  // 执行操作
  applyAction: async (
    sessionId: string,
    data: {
      finding_id: string
      action_type: 'confirm' | 'reject' | 'downgrade' | 'upgrade' | 'add_note'
      new_severity?: string
      reason?: string
    }
  ) => {
    const res = await api.post(`/review/sessions/${sessionId}/actions`, data)
    return res.data
  },

  // 关闭会话
  closeSession: async (sessionId: string) => {
    const res = await api.post(`/review/sessions/${sessionId}/close`)
    return res.data
  },

  // 会话列表
  listSessions: async (reportId: string) => {
    const res = await api.get<{
      items: Array<{ id: string; is_active: boolean; created_at: string; updated_at: string; message_count: number }>
      total: number
    }>(`/review/sessions/list/${reportId}`)
    return res.data
  },

  // 删除会话
  deleteSession: async (sessionId: string) => {
    const res = await api.delete(`/review/sessions/${sessionId}`)
    return res.data
  },

  // 获取漏洞标记
  getMarks: async (reportId: string) => {
    const res = await api.get<{
      items: Record<string, { id: string; finding_id: string; mark_type: string; severity?: string; note?: string }>
    }>(`/review/marks/${reportId}`)
    return res.data.items
  },

  // 保存漏洞标记
  saveMark: async (reportId: string, data: { finding_id: string; mark_type: string; severity?: string; note?: string }) => {
    const res = await api.post(`/review/marks/${reportId}`, data)
    return res.data
  },

  // 删除漏洞标记
  deleteMark: async (reportId: string, findingId: string) => {
    const res = await api.delete(`/review/marks/${reportId}/${findingId}`)
    return res.data
  },

  // AI 提取结构化漏洞
  extractFinding: async (analysis: string) => {
    const res = await api.post<{
      title: string
      severity: string
      category: string
      location: string
      description: string
      proof: string
      attack_scenario: string
      code_snippet: string
      recommendation: string
      error?: string
    }>('/review/extract-finding', { analysis }, { timeout: 60000 })
    return res.data
  },
}

// ============ Rules API ============

export interface SystemRule {
  id: number
  name: string
  display_name: string
  description: string | null
  blockchain: string | null
  category: string
  is_enabled: boolean
  priority: number
  trigger_count: number
  last_triggered_at: string | null
  created_at: string
  updated_at: string
}

export interface RuleStats {
  total: number
  enabled: number
  disabled: number
  by_category: Record<string, number>
  total_triggers: number
}

export interface MatchConfig {
  title_contains?: string[]
  description_contains?: string[]
  function_pattern?: string
  file_pattern?: string
  severity_in?: string[]
  match_all?: boolean
}

export interface CustomExclusion {
  id: string
  owner_id: string
  project_id: string | null
  blockchain: string | null
  name: string
  description: string | null
  match_config: MatchConfig
  is_enabled: boolean
  trigger_count: number
  created_at: string
  updated_at: string
}

export const rulesApi = {
  // 获取系统规则列表
  listSystemRules: async (params?: { blockchain?: string; category?: string; enabled_only?: boolean }) => {
    const res = await api.get<SystemRule[]>('/rules/system', { params })
    return res.data
  },

  // 获取单个系统规则
  getSystemRule: async (id: number) => {
    const res = await api.get<SystemRule>(`/rules/system/${id}`)
    return res.data
  },

  // 更新系统规则
  updateSystemRule: async (id: number, data: { is_enabled?: boolean; priority?: number }) => {
    const res = await api.put<SystemRule>(`/rules/system/${id}`, data)
    return res.data
  },

  // 批量更新系统规则
  batchUpdateSystemRules: async (data: { rule_ids: number[]; is_enabled: boolean }) => {
    const res = await api.post<{ updated: number; is_enabled: boolean }>('/rules/system/batch-update', data)
    return res.data
  },

  // 获取系统规则统计
  getSystemRulesStats: async () => {
    const res = await api.get<RuleStats>('/rules/system/stats')
    return res.data
  },

  // 获取自定义排除规则列表
  listCustomExclusions: async (params?: { blockchain?: string; project_id?: string }) => {
    const res = await api.get<CustomExclusion[]>('/rules/custom', { params })
    return res.data
  },

  // 创建自定义排除规则
  createCustomExclusion: async (data: {
    name: string
    description?: string | null
    blockchain?: string | null
    project_id?: string
    match_config: CustomExclusion['match_config']
    is_enabled?: boolean
  }) => {
    const res = await api.post<CustomExclusion>('/rules/custom', data)
    return res.data
  },

  // 更新自定义排除规则
  updateCustomExclusion: async (id: string, data: {
    name?: string
    description?: string | null
    blockchain?: string | null
    match_config?: CustomExclusion['match_config']
    is_enabled?: boolean
  }) => {
    const res = await api.put<CustomExclusion>(`/rules/custom/${id}`, data)
    return res.data
  },

  // 删除自定义排除规则
  deleteCustomExclusion: async (id: string) => {
    const res = await api.delete(`/rules/custom/${id}`)
    return res.data
  },
}

export { api }
export default api
