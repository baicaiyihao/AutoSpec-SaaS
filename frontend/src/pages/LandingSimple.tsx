/**
 * Landing Page - 简化测试版
 */
import { Button } from 'antd'
import { useNavigate } from 'react-router-dom'

export default function LandingSimple() {
  const navigate = useNavigate()

  return (
    <div style={{ padding: '50px', textAlign: 'center' }}>
      <h1>AutoSpec - 智能合约审计平台</h1>
      <p>欢迎使用 AutoSpec</p>
      <Button type="primary" onClick={() => navigate('/login')}>
        登录
      </Button>
    </div>
  )
}
