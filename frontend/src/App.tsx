import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import ProtectedRoute from './components/ProtectedRoute'
import ErrorBoundary from './components/ErrorBoundary'
import MainLayout from './components/Layout'
import Login from './pages/Login'
import LoginNew from './pages/LoginNew'
import AdminLogin from './pages/AdminLogin'
import Dashboard from './pages/Dashboard'
import Projects from './pages/Projects'
import ProjectDetail from './pages/ProjectDetail'
import AuditList from './pages/AuditList'
import AuditExecution from './pages/AuditExecution'
import ReportPage from './pages/ReportPage'
import Review from './pages/Review'
import UserSettings from './pages/UserSettings'
import AdminUsers from './pages/AdminUsers'
import AdminSettings from './pages/AdminSettings'
import AdminRules from './pages/AdminRules'
import TokenPurchase from './pages/TokenPurchase'
import Landing from './pages/Landing'
import LandingSimple from './pages/LandingSimple'
import { SuiClientProvider, WalletProvider } from '@mysten/dapp-kit'
import { getFullnodeUrl } from '@mysten/sui/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntApp, Spin } from 'antd'
import '@mysten/dapp-kit/dist/index.css'

// Root route handler - shows Landing for unauthenticated, redirects authenticated users to dashboard
function RootRoute() {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Spin size="large" />
      </div>
    )
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  return <Landing />
}

// Sui 网络配置
const queryClient = new QueryClient()
const networks = {
  testnet: { url: getFullnodeUrl('testnet') },
  mainnet: { url: getFullnodeUrl('mainnet') },
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <SuiClientProvider networks={networks} defaultNetwork="testnet">
          <WalletProvider autoConnect={true}>
            <AuthProvider>
              <AntApp>
                <BrowserRouter>
              <Routes>
                {/* Root - Landing for unauthenticated, redirect to dashboard for authenticated */}
                <Route path="/" element={<RootRoute />} />

                {/* 公开路由 */}
                <Route path="/login" element={<LoginNew />} />
                <Route path="/admin-login" element={<AdminLogin />} />
                <Route path="/login-old" element={<Login />} />

          {/* 受保护路由 - MainLayout wrapper */}
          <Route
            element={
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          >
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/projects/:id" element={<ProjectDetail />} />
            <Route path="/audits" element={<AuditList />} />
            <Route path="/audits/:id" element={<AuditExecution />} />
            <Route path="/review/:reportId" element={<Review />} />
            <Route path="/user-settings" element={<UserSettings />} />
            <Route path="/token-purchase" element={<TokenPurchase />} />
            <Route
              path="/admin/users"
              element={
                <ProtectedRoute requireAdmin>
                  <AdminUsers />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/settings"
              element={
                <ProtectedRoute requireAdmin>
                  <AdminSettings />
                </ProtectedRoute>
              }
            />
            <Route
              path="/admin/rules"
              element={
                <ProtectedRoute requireAdmin>
                  <AdminRules />
                </ProtectedRoute>
              }
            />
          </Route>

          {/* 报告详情 - 全屏布局 */}
          <Route
            path="/reports/:id"
            element={
              <ProtectedRoute>
                <ReportPage />
              </ProtectedRoute>
            }
          />
        </Routes>
        </BrowserRouter>
              </AntApp>
      </AuthProvider>
          </WalletProvider>
        </SuiClientProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
