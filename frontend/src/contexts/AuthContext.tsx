/**
 * Auth Context - 认证状态管理
 */
import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import type { ReactNode } from 'react'
import type { UserInfo } from '../types/auth'

interface AuthState {
  user: UserInfo | null
  token: string | null
  isLoading: boolean
}

interface AuthContextType extends AuthState {
  login: (token: string, user: UserInfo, refreshToken?: string) => void
  logout: () => void
  refreshUser: () => Promise<void>  // 🔥 刷新用户信息
  updateUser: (updates: Partial<UserInfo>) => void  // 🔥 直接更新用户信息
  isAdmin: boolean
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | null>(null)

const TOKEN_KEY = 'autospec_token'
const REFRESH_TOKEN_KEY = 'autospec_refresh_token'  // 🔥 Refresh token
const USER_KEY = 'autospec_user'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    token: null,
    isLoading: true,
  })

  // 初始化：从 localStorage 恢复
  useEffect(() => {
    const token = localStorage.getItem(TOKEN_KEY)
    const userStr = localStorage.getItem(USER_KEY)
    if (token && userStr) {
      try {
        const user = JSON.parse(userStr) as UserInfo
        setState({ user, token, isLoading: false })
      } catch {
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(USER_KEY)
        setState({ user: null, token: null, isLoading: false })
      }
    } else {
      setState({ user: null, token: null, isLoading: false })
    }
  }, [])

  const login = useCallback((token: string, user: UserInfo, refreshToken?: string) => {
    localStorage.setItem(TOKEN_KEY, token)
    localStorage.setItem(USER_KEY, JSON.stringify(user))
    if (refreshToken) {
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)  // 🔥 保存 refresh token
    }
    setState({ user, token, isLoading: false })
  }, [])

  const logout = useCallback(async () => {
    // 🔥 撤销 refresh token
    const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
    if (refreshToken) {
      try {
        const { authApi } = await import('../services/api')
        await authApi.logout(refreshToken)
      } catch {
        // 忽略错误
      }
    }

    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(REFRESH_TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    setState({ user: null, token: null, isLoading: false })
  }, [])

  const refreshUser = useCallback(async () => {
    // 🔥 刷新用户信息（从后端获取最新数据）
    if (!state.token) return

    try {
      const { authApi } = await import('../services/api')
      const user = await authApi.getCurrentUser()
      localStorage.setItem(USER_KEY, JSON.stringify(user))
      setState((prev) => ({ ...prev, user }))
    } catch (error) {
      // 静默失败 - 不影响用户体验
      console.warn('刷新用户信息失败（静默失败）:', error)
      // 不抛出错误，避免触发全局错误处理
    }
  }, [state.token])

  const updateUser = useCallback((updates: Partial<UserInfo>) => {
    // 🔥 直接更新用户信息（用于购买成功后立即更新余额）
    if (!state.user) return

    const updatedUser = { ...state.user, ...updates }
    localStorage.setItem(USER_KEY, JSON.stringify(updatedUser))
    setState((prev) => ({ ...prev, user: updatedUser }))
  }, [state.user])

  const value: AuthContextType = {
    ...state,
    login,
    logout,
    refreshUser,
    updateUser,
    isAdmin: state.user?.role === 'admin',
    isAuthenticated: !!state.token,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}

/**
 * 获取当前 token (供 API 拦截器使用)
 */
export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

/**
 * 获取当前 refresh token
 */
export function getStoredRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY)
}

/**
 * 更新 access token（刷新后）
 */
export function updateStoredToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}
