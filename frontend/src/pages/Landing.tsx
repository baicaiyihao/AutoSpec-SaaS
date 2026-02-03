/**
 * Landing Page - 简洁版
 */
import { Button, Row, Col, Card, Typography } from 'antd'
import { SecurityScanOutlined, RocketOutlined, ThunderboltOutlined, WalletOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'

const { Title, Paragraph } = Typography

export default function Landing() {
  const navigate = useNavigate()

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
      {/* Header */}
      <header style={{ background: 'rgba(255,255,255,0.95)', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>
        <div style={{ maxWidth: 1200, margin: '0 auto', padding: '20px 40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <SecurityScanOutlined style={{ fontSize: 36, color: '#667eea' }} />
            <span style={{ fontSize: 28, fontWeight: 'bold', color: '#333' }}>AutoSpec</span>
          </div>
          <Button type="primary" size="large" onClick={() => navigate('/login')}>
            开始使用
          </Button>
        </div>
      </header>

      {/* Hero */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '120px 40px', textAlign: 'center', color: '#fff' }}>
        <Title level={1} style={{ fontSize: 56, color: '#fff', marginBottom: 24, fontWeight: 800 }}>
          智能合约 AI 自动化审计
        </Title>
        <Paragraph style={{ fontSize: 24, color: 'rgba(255,255,255,0.9)', marginBottom: 48, maxWidth: 800, margin: '0 auto 48px' }}>
          支持 Sui Move 生态 · 基于大语言模型 · 全自动漏洞检测
        </Paragraph>

        <Button
          type="primary"
          size="large"
          icon={<WalletOutlined />}
          onClick={() => navigate('/login')}
          style={{
            height: 56,
            fontSize: 18,
            padding: '0 48px',
            background: '#fff',
            color: '#667eea',
            border: 'none',
            fontWeight: 600,
          }}
        >
          连接钱包开始
        </Button>
      </div>

      {/* Features */}
      <div style={{ maxWidth: 1200, margin: '0 auto', padding: '80px 40px' }}>
        <Row gutter={[32, 32]}>
          <Col xs={24} md={8}>
            <Card
              style={{
                background: 'rgba(255,255,255,0.95)',
                borderRadius: 16,
                border: 'none',
                height: '100%',
              }}
              bodyStyle={{ padding: 40 }}
            >
              <SecurityScanOutlined style={{ fontSize: 48, color: '#667eea', marginBottom: 16 }} />
              <Title level={3}>自动漏洞检测</Title>
              <Paragraph style={{ fontSize: 16, color: '#666' }}>
                AI 驱动的智能分析引擎，自动识别智能合约安全漏洞
              </Paragraph>
            </Card>
          </Col>
          <Col xs={24} md={8}>
            <Card
              style={{
                background: 'rgba(255,255,255,0.95)',
                borderRadius: 16,
                border: 'none',
                height: '100%',
              }}
              bodyStyle={{ padding: 40 }}
            >
              <RocketOutlined style={{ fontSize: 48, color: '#667eea', marginBottom: 16 }} />
              <Title level={3}>形式化验证</Title>
              <Paragraph style={{ fontSize: 16, color: '#666' }}>
                集成 Sui Move Prover，提供数学级别的安全保障
              </Paragraph>
            </Card>
          </Col>
          <Col xs={24} md={8}>
            <Card
              style={{
                background: 'rgba(255,255,255,0.95)',
                borderRadius: 16,
                border: 'none',
                height: '100%',
              }}
              bodyStyle={{ padding: 40 }}
            >
              <ThunderboltOutlined style={{ fontSize: 48, color: '#667eea', marginBottom: 16 }} />
              <Title level={3}>灵活计费</Title>
              <Paragraph style={{ fontSize: 16, color: '#666' }}>
                购买 LLM Tokens 或使用自己的 API Key，基础审计低至 $0.025
              </Paragraph>
            </Card>
          </Col>
        </Row>
      </div>

      {/* Footer */}
      <footer style={{ background: 'rgba(0,0,0,0.2)', color: '#fff', padding: '40px 0', marginTop: 80 }}>
        <div style={{ maxWidth: 1200, margin: '0 auto', padding: '0 40px', textAlign: 'center' }}>
          <Paragraph style={{ color: 'rgba(255,255,255,0.7)', marginBottom: 0 }}>
            © 2026 AutoSpec. Powered by Sui & Pyth Network.
          </Paragraph>
        </div>
      </footer>
    </div>
  )
}
