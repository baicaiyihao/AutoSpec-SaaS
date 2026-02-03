/**
 * Auth 相关类型
 */

export interface LoginRequest {
  username: string
  password: string
  captcha_id?: string      // 验证码 ID（如果启用）
  captcha_code?: string    // 用户输入的验证码
}

export interface RegisterRequest {
  username: string
  password: string
}

export interface UserInfo {
  id: string
  username: string
  role: 'admin' | 'user'
  is_active: boolean
  allow_shared_api_keys: boolean  // 🔥 是否允许使用共享 API Keys
  token_quota: number | null      // 🔥 Token 额度 (null = 无限)
  tokens_used: number             // 🔥 已使用 tokens（总计）
  tokens_used_own_key: number     // 🔥 使用自己 API Key 的 token 消耗
  tokens_used_platform: number    // 🔥 使用平台 Token 的消耗
  wallet_address: string | null   // 🔥 Sui 钱包地址
  token_balance: number           // 🔥 Token 余额（购买获得）
  payment_mode: 'own_key' | 'platform_token'  // 🔥 付费模式
  created_at: string
}

export interface TokenResponse {
  access_token: string
  refresh_token?: string  // 🔥 Refresh token (长期)
  token_type: string
  user: UserInfo
  pending?: boolean
  password_must_change?: boolean  // 🔥 是否需要强制修改密码
}

export interface ApiKeysStatus {
  dashscope: boolean
  anthropic: boolean
  openai: boolean
  deepseek: boolean
  zhipu: boolean
}

export interface ApiKeysUpdate {
  dashscope?: string
  anthropic?: string
  openai?: string
  deepseek?: string
  zhipu?: string
}

export interface AuditConfig {
  model_preset: string
  agent_architecture: string
  max_retries: number
  enable_security_scan: boolean
}

export interface SystemSetting {
  key: string
  value: string
  value_type: string
  category: string
  description?: string
  updated_at?: string
}

export interface PresetAgentConfig {
  provider: string
  model: string
  max_tokens?: number | null
  fallback_provider?: string | null
  fallback_model?: string | null
}

export interface PresetTemplate {
  name: string
  description: string
  builtin: boolean
  agents: Record<string, PresetAgentConfig>
}

export interface ServerApiKeyStatus {
  key: string
  label: string
  provider: string
  source: 'none' | 'env' | 'db' | 'both'
}

export interface PresetCreateRequest {
  key: string
  name: string
  description?: string
  agents: Record<string, PresetAgentConfig>
}

export interface PresetUpdateRequest {
  name?: string
  description?: string
  agents?: Record<string, PresetAgentConfig>
}

export interface PaymentModeInfo {
  payment_mode: 'own_key' | 'platform_token'
  tokens_used_own_key: number
  tokens_used_platform: number
  token_balance: number
}

export interface PaymentModeUpdateRequest {
  payment_mode: 'own_key' | 'platform_token'
}
