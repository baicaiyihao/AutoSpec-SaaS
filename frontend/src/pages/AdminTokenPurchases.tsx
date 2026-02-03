/**
 * 管理员 - Token 充值审核页面
 *
 * 功能：
 * - 查看所有用户的充值记录
 * - 筛选需要审核的记录（价格偏差大）
 * - 手动确认/拒绝充值
 */
import { useState, useEffect } from 'react'
import {
  Table, Tag, Button, message, Space, Card, Statistic, Row, Col,
  Typography, Modal, Input, Select, DatePicker, Alert,
} from 'antd'
import {
  CheckCircleOutlined, CloseCircleOutlined, ExclamationCircleOutlined,
  WalletOutlined, DollarOutlined,
} from '@ant-design/icons'
import dayjs from 'dayjs'

const { Title, Text } = Typography
const { TextArea } = Input
const { RangePicker } = DatePicker

interface TokenPurchase {
  id: string
  user_id: string
  user_name: string  // 添加用户名显示
  transaction_digest: string
  wallet_address: string
  sui_amount: number  // MIST
  usd_amount: number  // cents
  sui_usd_price: number
  token_amount: number
  token_usd_price: number
  status: 'pending' | 'confirmed' | 'failed'
  error_message: string | null
  blockchain_timestamp: string | null
  confirmed_at: string | null
  created_at: string
}

interface PurchaseStats {
  total_purchases: number
  pending_count: number
  confirmed_count: number
  failed_count: number
  total_sui_amount: number
  total_usd_amount: number
  total_tokens: number
}

export default function AdminTokenPurchases() {
  const [purchases, setPurchases] = useState<TokenPurchase[]>([])
  const [stats, setStats] = useState<PurchaseStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'pending' | 'confirmed' | 'failed'>('all')
  const [reviewModal, setReviewModal] = useState<{
    visible: boolean
    purchase: TokenPurchase | null
    action: 'approve' | 'reject' | null
  }>({
    visible: false,
    purchase: null,
    action: null,
  })
  const [reviewNote, setReviewNote] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      // TODO: 调用实际 API
      // const data = await adminApi.getTokenPurchases()
      // setPurchases(data.purchases)
      // setStats(data.stats)

      // Mock 数据
      const mockPurchases: TokenPurchase[] = [
        {
          id: '1',
          user_id: 'user1',
          user_name: 'alice@example.com',
          transaction_digest: '0xabc123...',
          wallet_address: '0x1234567890abcdef...',
          sui_amount: 3500000000,
          usd_amount: 1000,
          sui_usd_price: 2.86,
          token_amount: 1000,
          token_usd_price: 0.01,
          status: 'failed',
          error_message: '价格偏差过大: 8.50% (用户: $2.86, 当前: $3.10)',
          blockchain_timestamp: '2026-02-02T08:00:00Z',
          confirmed_at: null,
          created_at: '2026-02-02T08:00:10Z',
        },
        {
          id: '2',
          user_id: 'user2',
          user_name: 'bob@example.com',
          transaction_digest: '0xdef456...',
          wallet_address: '0xabcdef1234567890...',
          sui_amount: 5000000000,
          usd_amount: 1500,
          sui_usd_price: 3.00,
          token_amount: 1500,
          token_usd_price: 0.01,
          status: 'confirmed',
          error_message: null,
          blockchain_timestamp: '2026-02-02T07:30:00Z',
          confirmed_at: '2026-02-02T07:30:05Z',
          created_at: '2026-02-02T07:30:05Z',
        },
      ]

      setPurchases(mockPurchases)
      setStats({
        total_purchases: 2,
        pending_count: 0,
        confirmed_count: 1,
        failed_count: 1,
        total_sui_amount: 8500000000,
        total_usd_amount: 2500,
        total_tokens: 2500,
      })
    } catch (err: any) {
      message.error('加载充值记录失败')
    } finally {
      setLoading(false)
    }
  }

  const openReviewModal = (purchase: TokenPurchase, action: 'approve' | 'reject') => {
    setReviewModal({
      visible: true,
      purchase,
      action,
    })
    setReviewNote('')
  }

  const handleReview = async () => {
    if (!reviewModal.purchase) return

    try {
      // TODO: 调用实际 API
      // await adminApi.reviewTokenPurchase(reviewModal.purchase.id, {
      //   action: reviewModal.action,
      //   note: reviewNote,
      // })

      message.success(
        reviewModal.action === 'approve'
          ? '已批准充值，Token 已发放到用户账户'
          : '已拒绝充值'
      )
      setReviewModal({ visible: false, purchase: null, action: null })
      loadData()
    } catch (err: any) {
      message.error('操作失败')
    }
  }

  const filteredPurchases = purchases.filter(p => {
    if (filter === 'all') return true
    return p.status === filter
  })

  const statusColors = {
    pending: 'processing',
    confirmed: 'success',
    failed: 'error',
  } as const

  const statusLabels = {
    pending: '待确认',
    confirmed: '已确认',
    failed: '需审核',
  } as const

  const columns = [
    {
      title: '用户',
      dataIndex: 'user_name',
      key: 'user_name',
      width: 180,
    },
    {
      title: '交易哈希',
      dataIndex: 'transaction_digest',
      key: 'transaction_digest',
      width: 150,
      render: (text: string) => (
        <Text code copyable={{ text }}>
          {text.slice(0, 10)}...
        </Text>
      ),
    },
    {
      title: 'SUI 金额',
      dataIndex: 'sui_amount',
      key: 'sui_amount',
      align: 'right' as const,
      width: 120,
      render: (amount: number) => `${(amount / 1e9).toFixed(4)} SUI`,
    },
    {
      title: 'USD 金额',
      dataIndex: 'usd_amount',
      key: 'usd_amount',
      align: 'right' as const,
      width: 100,
      render: (amount: number) => `$${(amount / 100).toFixed(2)}`,
    },
    {
      title: 'Token 数量',
      dataIndex: 'token_amount',
      key: 'token_amount',
      align: 'right' as const,
      width: 100,
    },
    {
      title: 'SUI/USD 价格',
      dataIndex: 'sui_usd_price',
      key: 'sui_usd_price',
      align: 'right' as const,
      width: 120,
      render: (price: number) => `$${price.toFixed(4)}`,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <Tag color={statusColors[status as keyof typeof statusColors]}>
          {statusLabels[status as keyof typeof statusLabels]}
        </Tag>
      ),
    },
    {
      title: '时间',
      dataIndex: 'blockchain_timestamp',
      key: 'blockchain_timestamp',
      width: 160,
      render: (text: string) => text ? dayjs(text).format('YYYY-MM-DD HH:mm:ss') : '-',
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_: any, record: TokenPurchase) => (
        <Space>
          {record.status === 'failed' && (
            <>
              <Button
                type="primary"
                size="small"
                icon={<CheckCircleOutlined />}
                onClick={() => openReviewModal(record, 'approve')}
              >
                批准
              </Button>
              <Button
                danger
                size="small"
                icon={<CloseCircleOutlined />}
                onClick={() => openReviewModal(record, 'reject')}
              >
                拒绝
              </Button>
            </>
          )}
          {record.status === 'confirmed' && (
            <Text type="success">已完成</Text>
          )}
        </Space>
      ),
    },
  ]

  return (
    <div className="max-w-7xl mx-auto">
      <Title level={2}>Token 充值管理</Title>

      {/* 统计卡片 */}
      {stats && (
        <Row gutter={16} className="mb-6">
          <Col span={6}>
            <Card>
              <Statistic
                title="总充值次数"
                value={stats.total_purchases}
                prefix={<WalletOutlined />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="需审核"
                value={stats.failed_count}
                valueStyle={{ color: '#f5222d' }}
                prefix={<ExclamationCircleOutlined />}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="总 USD 金额"
                value={(stats.total_usd_amount / 100).toFixed(2)}
                prefix="$"
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="总 Token 发放"
                value={stats.total_tokens}
              />
            </Card>
          </Col>
        </Row>
      )}

      {/* 筛选器 */}
      <Card className="mb-4">
        <Space>
          <Select
            value={filter}
            onChange={setFilter}
            style={{ width: 120 }}
            options={[
              { value: 'all', label: '全部' },
              { value: 'failed', label: '需审核' },
              { value: 'confirmed', label: '已确认' },
              { value: 'pending', label: '待确认' },
            ]}
          />
          <Button onClick={loadData}>刷新</Button>
        </Space>
      </Card>

      {/* 充值记录表 */}
      <Card>
        <Table
          columns={columns}
          dataSource={filteredPurchases}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 20,
            showTotal: (total) => `共 ${total} 条记录`,
          }}
          expandable={{
            expandedRowRender: (record) => (
              <div className="p-4 bg-gray-50">
                <Space direction="vertical" className="w-full">
                  <div>
                    <Text strong>钱包地址：</Text>
                    <Text code copyable={{ text: record.wallet_address }}>
                      {record.wallet_address}
                    </Text>
                  </div>
                  {record.error_message && (
                    <div>
                      <Text strong type="danger">错误信息：</Text>
                      <Text type="danger">{record.error_message}</Text>
                    </div>
                  )}
                  <div>
                    <Text strong>Token 单价：</Text>
                    <Text>${record.token_usd_price.toFixed(4)}</Text>
                  </div>
                  <div>
                    <Text strong>确认时间：</Text>
                    <Text>{record.confirmed_at ? dayjs(record.confirmed_at).format('YYYY-MM-DD HH:mm:ss') : '-'}</Text>
                  </div>
                </Space>
              </div>
            ),
          }}
        />
      </Card>

      {/* 审核弹窗 */}
      <Modal
        title={reviewModal.action === 'approve' ? '批准充值' : '拒绝充值'}
        open={reviewModal.visible}
        onOk={handleReview}
        onCancel={() => setReviewModal({ visible: false, purchase: null, action: null })}
        okText={reviewModal.action === 'approve' ? '批准' : '拒绝'}
        okButtonProps={{ danger: reviewModal.action === 'reject' }}
      >
        {reviewModal.purchase && (
          <Space direction="vertical" className="w-full">
            <div>
              <Text strong>用户：</Text>
              <Text>{reviewModal.purchase.user_name}</Text>
            </div>
            <div>
              <Text strong>SUI 金额：</Text>
              <Text>{(reviewModal.purchase.sui_amount / 1e9).toFixed(4)} SUI</Text>
            </div>
            <div>
              <Text strong>Token 数量：</Text>
              <Text>{reviewModal.purchase.token_amount}</Text>
            </div>
            {reviewModal.purchase.error_message && (
              <div>
                <Text strong type="danger">错误信息：</Text>
                <Text type="danger">{reviewModal.purchase.error_message}</Text>
              </div>
            )}
            <div>
              <Text strong>备注（可选）：</Text>
              <TextArea
                rows={3}
                value={reviewNote}
                onChange={(e) => setReviewNote(e.target.value)}
                placeholder="输入审核备注..."
              />
            </div>
            {reviewModal.action === 'approve' && (
              <Alert
                message="批准后将立即给用户充值 Token"
                type="warning"
                showIcon
              />
            )}
          </Space>
        )}
      </Modal>
    </div>
  )
}
