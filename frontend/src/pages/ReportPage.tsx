import { useState } from 'react'
import { useParams, useNavigate, useLocation } from 'react-router-dom'
import { Tabs, Button } from 'antd'
import { ArrowLeftOutlined } from '@ant-design/icons'
import ReportOverview from './ReportOverview'
import CodeAuditView from './CodeAuditView'

export default function ReportPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const initialTab = (location.state as { tab?: string })?.tab || 'overview'
  const [activeTab, setActiveTab] = useState(initialTab)

  return (
    <div className="h-screen flex flex-col">
      {/* 顶部：返回按钮 + 标签页 */}
      <div className="flex items-center px-4 border-b bg-white" style={{ height: 48 }}>
        <Button
          icon={<ArrowLeftOutlined />}
          type="text"
          onClick={() => navigate('/audits')}
        >
          返回
        </Button>
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          className="ml-4 report-page-tabs"
          style={{ marginBottom: 0 }}
          items={[
            { key: 'overview', label: '报告概览' },
            { key: 'audit', label: '漏洞审计' },
          ]}
        />
      </div>

      {/* 标签页内容 */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'overview' ? (
          <div className="h-full overflow-auto p-4">
            <ReportOverview reportId={id!} />
          </div>
        ) : (
          <CodeAuditView reportId={id!} embedded />
        )}
      </div>
    </div>
  )
}
