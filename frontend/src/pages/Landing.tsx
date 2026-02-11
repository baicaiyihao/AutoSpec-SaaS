/**
 * Landing Page - 基于真实功能
 * 参考 README.md 的准确描述
 */
import { Button, Row, Col, Card, Typography } from 'antd'
import {
  SecurityScanOutlined,
  RocketOutlined,
  CheckCircleOutlined,
  ThunderboltOutlined,
  SafetyOutlined,
  ApiOutlined,
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import './Landing.css'

const { Title, Paragraph } = Typography

export default function Landing() {
  const navigate = useNavigate()

  return (
    <div className="landing-page">
      {/* Header */}
      <header className="landing-header">
        <div className="container">
          <div className="header-content">
            <div className="logo">
              <SecurityScanOutlined className="logo-icon" />
              <span className="logo-text">AutoSpec</span>
            </div>
            <Button type="primary" size="large" onClick={() => navigate('/login')}>
              开始使用
            </Button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero-section">
        <div className="container">
          <div className="hero-content">
            <div className="hero-badge">
              <SafetyOutlined /> Sui Move 智能合约安全审计
            </div>
            <Title level={1} className="hero-title">
              AI 驱动的
              <br />
              <span className="gradient-text">智能合约自动化审计</span>
            </Title>
            <Paragraph className="hero-subtitle">
              基于多代理 AI 系统的智能合约安全审计平台
              <br />
              <strong>漏洞扫描 + 多视角验证 + 攻击链分析</strong>
            </Paragraph>

            <Button
              type="primary"
              size="large"
              icon={<RocketOutlined />}
              onClick={() => navigate('/login')}
              className="hero-button-primary"
            >
              连接钱包开始审计
            </Button>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="features-section">
        <div className="container">
          <div className="section-header">
            <Title level={2}>核心功能</Title>
            <Paragraph className="section-subtitle">
              三阶段审计流程，从代码分析到攻击链验证
            </Paragraph>
          </div>

          <Row gutter={[24, 24]}>
            {/* Feature 1 */}
            <Col xs={24} md={12} lg={8}>
              <Card className="feature-card" hoverable>
                <div className="feature-icon" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
                  <SecurityScanOutlined />
                </div>
                <Title level={4}>多代理审计系统</Title>
                <Paragraph className="feature-desc">
                  三阶段智能审计流程：
                </Paragraph>
                <ul className="feature-list">
                  <li><CheckCircleOutlined /> <strong>Phase 1</strong>: 代码分析（调用图、依赖解析）</li>
                  <li><CheckCircleOutlined /> <strong>Phase 2</strong>: 漏洞扫描（规则 + AI）</li>
                  <li><CheckCircleOutlined /> <strong>Phase 3</strong>: 多视角验证（3-in-1）</li>
                  <li><CheckCircleOutlined /> <strong>Phase 4</strong>: 攻击链分析（HIGH/CRITICAL）</li>
                </ul>
              </Card>
            </Col>

            {/* Feature 2 */}
            <Col xs={24} md={12} lg={8}>
              <Card className="feature-card" hoverable>
                <div className="feature-icon" style={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
                  <SafetyOutlined />
                </div>
                <Title level={4}>智能误报过滤</Title>
                <Paragraph className="feature-desc">
                  27+ 内置排除规则 + AI 复审：
                </Paragraph>
                <ul className="feature-list">
                  <li><CheckCircleOutlined /> Move 语言保护（溢出 abort、类型安全）</li>
                  <li><CheckCircleOutlined /> Sui Move 模式（Capability、public(package)）</li>
                  <li><CheckCircleOutlined /> 生产合约模式（Cetus CLMM 案例）</li>
                  <li><CheckCircleOutlined /> 非安全问题自动排除（常量、Mock）</li>
                </ul>
              </Card>
            </Col>

            {/* Feature 3 */}
            <Col xs={24} md={12} lg={8}>
              <Card className="feature-card" hoverable>
                <div className="feature-icon" style={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
                  <ApiOutlined />
                </div>
                <Title level={4}>多视角验证</Title>
                <Paragraph className="feature-desc">
                  统一 Verifier Agent 整合 3 种专家视角：
                </Paragraph>
                <ul className="feature-list">
                  <li><CheckCircleOutlined /> <strong>Security Auditor</strong>: 已知漏洞模式</li>
                  <li><CheckCircleOutlined /> <strong>Move Expert</strong>: 类型系统保护</li>
                  <li><CheckCircleOutlined /> <strong>Business Analyst</strong>: 攻击经济学</li>
                  <li><CheckCircleOutlined /> 置信度 &lt; 80% 触发 Manager 复审</li>
                </ul>
              </Card>
            </Col>

            {/* Feature 4 */}
            <Col xs={24} md={12} lg={8}>
              <Card className="feature-card" hoverable>
                <div className="feature-icon" style={{ background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)' }}>
                  <ThunderboltOutlined />
                </div>
                <Title level={4}>双计费模式</Title>
                <Paragraph className="feature-desc">
                  灵活的付费方式，成本透明：
                </Paragraph>
                <ul className="feature-list">
                  <li><CheckCircleOutlined /> <strong>own_key</strong>: 使用自己的 API Key</li>
                  <li><CheckCircleOutlined /> <strong>platform_token</strong>: 用 SUI 购买 Token</li>
                  <li><CheckCircleOutlined /> 链上充值（Pyth 实时汇率）</li>
                  <li><CheckCircleOutlined /> 实时用量统计与扣费</li>
                </ul>
              </Card>
            </Col>

            {/* Feature 5 */}
            <Col xs={24} md={12} lg={8}>
              <Card className="feature-card" hoverable>
                <div className="feature-icon" style={{ background: 'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)' }}>
                  <SecurityScanOutlined />
                </div>
                <Title level={4}>完整报告系统</Title>
                <Paragraph className="feature-desc">
                  详细的审计报告与代码定位：
                </Paragraph>
                <ul className="feature-list">
                  <li><CheckCircleOutlined /> 漏洞分级（CRITICAL/HIGH/MEDIUM/LOW）</li>
                  <li><CheckCircleOutlined /> Monaco Editor 代码跳转</li>
                  <li><CheckCircleOutlined /> AI Review 对话复审</li>
                  <li><CheckCircleOutlined /> Markdown/JSON 导出</li>
                </ul>
              </Card>
            </Col>

            {/* Feature 6 */}
            <Col xs={24} md={12} lg={8}>
              <Card className="feature-card" hoverable>
                <div className="feature-icon" style={{ background: 'linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%)' }}>
                  <RocketOutlined />
                </div>
                <Title level={4}>Web3 原生设计</Title>
                <Paragraph className="feature-desc">
                  去中心化身份与支付：
                </Paragraph>
                <ul className="feature-list">
                  <li><CheckCircleOutlined /> Sui 钱包签名登录（无需密码）</li>
                  <li><CheckCircleOutlined /> 链上 Token 充值（可追溯）</li>
                  <li><CheckCircleOutlined /> 角色权限管理（Admin/User）</li>
                  <li><CheckCircleOutlined /> 自定义规则库</li>
                </ul>
              </Card>
            </Col>
          </Row>
        </div>
      </section>

      {/* Workflow Section */}
      <section className="workflow-section">
        <div className="container">
          <div className="section-header">
            <Title level={2}>使用流程</Title>
            <Paragraph className="section-subtitle">
              4 步完成智能合约安全审计
            </Paragraph>
          </div>

          <Row gutter={[48, 48]} align="middle">
            <Col xs={24} md={12} lg={6}>
              <div className="workflow-step">
                <div className="step-number">1</div>
                <Title level={4}>连接钱包</Title>
                <Paragraph>
                  使用 Sui 钱包签名登录，自动创建账户
                </Paragraph>
              </div>
            </Col>
            <Col xs={24} md={12} lg={6}>
              <div className="workflow-step">
                <div className="step-number">2</div>
                <Title level={4}>配置付费</Title>
                <Paragraph>
                  选择 own_key 或购买 platform_token
                </Paragraph>
              </div>
            </Col>
            <Col xs={24} md={12} lg={6}>
              <div className="workflow-step">
                <div className="step-number">3</div>
                <Title level={4}>上传代码</Title>
                <Paragraph>
                  上传 Move 源码或导入本地项目
                </Paragraph>
              </div>
            </Col>
            <Col xs={24} md={12} lg={6}>
              <div className="workflow-step">
                <div className="step-number">4</div>
                <Title level={4}>查看报告</Title>
                <Paragraph>
                  实时监控进度，审查漏洞，导出报告
                </Paragraph>
              </div>
            </Col>
          </Row>
        </div>
      </section>

      {/* CTA Section */}
      <section className="cta-section">
        <div className="container">
          <div className="cta-content">
            <Title level={2} className="cta-title">
              开始使用 AutoSpec
            </Title>
            <Paragraph className="cta-subtitle">
              连接 Sui 钱包，立即开始智能合约安全审计
            </Paragraph>
            <Button
              type="primary"
              size="large"
              icon={<RocketOutlined />}
              onClick={() => navigate('/login')}
              className="cta-button"
            >
              立即开始
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="container">
          <div className="footer-bottom">
            <Paragraph className="footer-copyright">
              © 2026 AutoSpec. All rights reserved.
            </Paragraph>
          </div>
        </div>
      </footer>
    </div>
  )
}
