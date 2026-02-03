/**
 * Token 充值页面
 *
 * 用户通过连接钱包，使用 SUI 购买 AutoSpec Token
 */
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Card,
  Form,
  InputNumber,
  Button,
  Space,
  Statistic,
  Alert,
  Divider,
  Typography,
  message,
  Result,
} from 'antd'
import {
  WalletOutlined,
  DollarOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { useCurrentAccount, useSignAndExecuteTransaction, useSuiClient } from '@mysten/dapp-kit'
import { Transaction } from '@mysten/sui/transactions'
import { SuiPriceServiceConnection, SuiPythClient } from '@pythnetwork/pyth-sui-js'
import { useSuiPrice } from '../hooks/useSuiPrice'
import { SUI_CONTRACT, SUI_UNITS, PYTH_PRICE_FEED, PYTH_WORMHOLE_STATE } from '../config/sui'
import { api } from '../services/api'
import { useAuth } from '../contexts/AuthContext'
import WalletButton from '../components/WalletButton'

const { Title, Text, Paragraph } = Typography

interface PricingConfig {
  price_per_1k_tokens: number  // 每千 LLM tokens 的美元价格
  price_tolerance: number
}

export default function TokenPurchase() {
  const navigate = useNavigate()
  const currentAccount = useCurrentAccount()
  const client = useSuiClient()
  const { mutate: signAndExecute, isPending: isExecuting } = useSignAndExecuteTransaction()
  const { price: suiPrice, loading: priceLoading, error: priceError } = useSuiPrice()
  const { updateUser, refreshUser } = useAuth()  // 🔥 用于更新用户信息

  const [form] = Form.useForm()
  const [tokenAmount, setTokenAmount] = useState<number>(50000)  // 默认购买 50,000 tokens
  const [pricingConfig, setPricingConfig] = useState<PricingConfig | null>(null)
  const [configLoading, setConfigLoading] = useState(true)
  const [purchaseSuccess, setPurchaseSuccess] = useState(false)
  const [transactionDigest, setTransactionDigest] = useState<string>('')

  // 加载定价配置
  useEffect(() => {
    loadPricingConfig()
  }, [])

  const loadPricingConfig = async () => {
    try {
      setConfigLoading(true)
      // 使用固定配置
      // 基于 Qwen-Plus: 输入 0.8元/百万 + 输出 2元/百万
      // 平均成本: ~1.4元/百万 ≈ $0.20/百万 = $0.0002/千token
      // 加服务费后: $0.0005/千token
      setPricingConfig({
        price_per_1k_tokens: 0.0005, // 每千 LLM tokens = $0.0005 USD
        price_tolerance: 0.05, // 5% 价格波动容忍度
      })
    } catch (error: any) {
      message.error('加载定价配置失败')
      console.error('Failed to load pricing config:', error)
    } finally {
      setConfigLoading(false)
    }
  }

  // 计算金额
  const calculateAmounts = () => {
    if (!pricingConfig || !suiPrice) {
      return { usdAmount: 0, suiAmount: 0, suiAmountMist: 0 }
    }

    // tokenAmount 是 LLM token 数量，按千计费
    const usdAmount = (tokenAmount / 1000) * pricingConfig.price_per_1k_tokens
    const suiAmount = usdAmount / suiPrice
    const suiAmountMist = Math.ceil(suiAmount * SUI_UNITS.MIST_PER_SUI)

    return { usdAmount, suiAmount, suiAmountMist }
  }

  const { usdAmount, suiAmount, suiAmountMist } = calculateAmounts()

  // 执行购买
  const handlePurchase = async () => {
    if (!currentAccount) {
      message.error('请先连接钱包')
      return
    }

    if (!pricingConfig || !suiPrice) {
      message.error('价格信息加载中，请稍候')
      return
    }

    try {
      // 完全照抄 Fate3AI 的实现
      const connection = new SuiPriceServiceConnection('https://hermes-beta.pyth.network')
      const priceIDs = [PYTH_PRICE_FEED.SUI_USD]
      const wormholeStateId = PYTH_WORMHOLE_STATE
      const pythStateId = SUI_CONTRACT.PYTH_STATE
      const suipythclient = new SuiPythClient(client, pythStateId, wormholeStateId)

      const tx = new Transaction()

      // 1. 获取 Pyth price update data
      const priceUpdateData = await connection.getPriceFeedsUpdateData(priceIDs)

      // 2. 更新 price feeds 并获取 price info object IDs
      const priceInfoObjectIds = await suipythclient.updatePriceFeeds(tx, priceUpdateData, priceIDs)

      // 3. 预估支付金额（前端显示用）
      const usdAmount = (tokenAmount / 1000) * pricingConfig.price_per_1k_tokens
      const suiAmountFloat = usdAmount / suiPrice
      const suiPayAmount = Math.ceil(suiAmountFloat * SUI_UNITS.MIST_PER_SUI) + 100000000  // 多给点 gas

      console.log('🔍 交易参数:')
      console.log('- tokenAmount:', tokenAmount)
      console.log('- suiPrice:', suiPrice)
      console.log('- suiPayAmount:', suiPayAmount)
      console.log('- priceInfoObjectId:', priceInfoObjectIds[0])

      // 4. 分割 coin
      const coin = tx.splitCoins(tx.gas, [suiPayAmount])
      tx.setGasBudget(10000000)

      // 5. 调用合约
      tx.moveCall({
        target: `${SUI_CONTRACT.PACKAGE_ID}::token_purchase::purchase_tokens`,
        arguments: [
          tx.object(coin),
          tx.pure.u64(tokenAmount),
          tx.object(SUI_CONTRACT.SUI_POOL_ID),
          tx.object(priceInfoObjectIds[0]),  // 动态生成的 price info object
          tx.object('0x6'),  // clock
        ],
      })

      // 6. 转回剩余的 coin
      tx.transferObjects([coin], currentAccount.address)

      // 签名并执行交易
      signAndExecute(
        {
          transaction: tx,
        },
        {
          onSuccess: async (result) => {
            const digest = result.digest
            setTransactionDigest(digest)

            message.loading('交易已提交，等待后端验证...', 0)

            // 提交到后端验证
            try {
              const res = await api.post('/tokens/purchase', { transaction_digest: digest })
              message.destroy()

              console.log('🔍 购买结果:', res.data)

              const result = res.data
              if (result.status === 'success') {
                message.success(`购买成功！获得 ${result.token_amount?.toLocaleString()} LLM Tokens`)

                // 🔥 直接更新用户余额（使用后端返回的 new_balance）
                if (result.new_balance !== undefined) {
                  updateUser({ token_balance: result.new_balance })
                }

                setPurchaseSuccess(true)
                form.resetFields()
              } else {
                message.warning(`交易已提交，但需要人工审核: ${result.message}`)
              }
            } catch (error: any) {
              message.destroy()
              console.error('🔍 购买失败:', error.response || error)

              const errorMsg = error.response?.data?.detail || error.message || '后端验证失败'

              // 如果是数组，取第一个错误
              const displayMsg = Array.isArray(errorMsg)
                ? errorMsg[0]?.msg || JSON.stringify(errorMsg)
                : (typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg))

              message.error(`购买失败: ${displayMsg}`)
            }
          },
          onError: (error) => {
            message.error(`交易失败: ${error.message}`)
            console.error('Transaction failed:', error)
          },
        }
      )
    } catch (error: any) {
      message.error(`购买失败: ${error.message}`)
      console.error('Purchase error:', error)
    }
  }

  // 成功页面
  if (purchaseSuccess) {
    return (
      <div style={{ padding: '24px', maxWidth: '800px', margin: '0 auto' }}>
        <Result
          status="success"
          title="购买成功！"
          subTitle={`交易哈希: ${transactionDigest.slice(0, 20)}...`}
          extra={[
            <Button type="primary" key="continue" onClick={() => setPurchaseSuccess(false)}>
              继续购买
            </Button>,
            <Button
              key="dashboard"
              onClick={async () => {
                // 刷新用户信息（更新 token_balance）
                await refreshUser()
                // 使用客户端路由跳转（不刷新页面，保留认证状态）
                navigate('/dashboard')
              }}
            >
              返回仪表板
            </Button>,
          ]}
        >
          <div style={{ background: '#fafafa', padding: '24px', borderRadius: '8px' }}>
            <Paragraph>
              <Text strong>购买数量:</Text> {tokenAmount.toLocaleString()} LLM Tokens
            </Paragraph>
            <Paragraph>
              <Text strong>支付金额:</Text> {suiAmount.toFixed(4)} SUI (≈ ${usdAmount.toFixed(4)})
            </Paragraph>
          </div>
        </Result>
      </div>
    )
  }

  // 主页面
  return (
    <div style={{ padding: '24px', maxWidth: '800px', margin: '0 auto' }}>
      <Card>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          {/* 标题 */}
          <div>
            <Title level={2}>
              <ThunderboltOutlined /> 购买 LLM Tokens
            </Title>
            <Paragraph type="secondary">
              使用 SUI 直接购买 LLM Tokens 进行智能合约审计
            </Paragraph>
            <Alert
              type="info"
              showIcon
              message="计费说明"
              description={
                <div>
                  <p><strong>• 直接购买 LLM Tokens，透明计费</strong></p>
                  <p>• 基础审计（小型合约）：约 50,000 Tokens ≈ $0.025</p>
                  <p>• 深度审计（复杂合约）：约 500,000 Tokens ≈ $0.25</p>
                  <p>• 也可以在"用户设置"中配置自己的 API Key，无需购买</p>
                </div>
              }
              style={{ marginTop: 16, textAlign: 'left' }}
            />
          </div>

          {/* 钱包连接 */}
          {!currentAccount && (
            <Alert
              message="请先连接钱包"
              description="您需要连接 Sui 钱包才能购买 Token"
              type="warning"
              showIcon
              action={<WalletButton />}
            />
          )}

          {currentAccount && (
            <>
              {/* 价格信息 */}
              <Card size="small" style={{ background: '#fafafa' }}>
                <Space size="large" wrap>
                  <Statistic
                    title="SUI 价格"
                    value={suiPrice || 0}
                    precision={4}
                    prefix={<DollarOutlined />}
                    suffix="USD"
                    loading={priceLoading}
                  />
                  <Statistic
                    title="定价"
                    value={pricingConfig?.price_per_1k_tokens || 0}
                    precision={4}
                    prefix={<DollarOutlined />}
                    suffix="/ 1K Tokens"
                    loading={configLoading}
                  />
                </Space>
              </Card>

              {priceError && <Alert message="价格加载失败" type="error" showIcon />}

              <Divider />

              {/* 购买表单 */}
              <Form form={form} layout="vertical" initialValues={{ amount: 50000 }}>
                <Form.Item
                  label="购买数量 (LLM Tokens)"
                  name="amount"
                  rules={[
                    { required: true, message: '请输入购买数量' },
                    { type: 'number', min: 1000, message: '最少购买 1,000 Tokens' },
                  ]}
                >
                  <InputNumber
                    style={{ width: '100%' }}
                    min={1000}
                    step={10000}
                    onChange={(value) => setTokenAmount(value || 0)}
                    addonAfter="Tokens"
                    size="large"
                    formatter={(value) => `${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}
                    parser={(value) => value?.replace(/,/g, '') as any}
                  />
                </Form.Item>

                {/* 费用明细 */}
                <Card size="small" title="费用明细" style={{ marginBottom: '16px' }}>
                  <Space direction="vertical" style={{ width: '100%' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Text>LLM Tokens:</Text>
                      <Text strong>{tokenAmount.toLocaleString()}</Text>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Text>单价:</Text>
                      <Text>${pricingConfig?.price_per_1k_tokens.toFixed(4)} / 1K</Text>
                    </div>
                    <Divider style={{ margin: '8px 0' }} />
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Text strong>总计 (USD):</Text>
                      <Text strong style={{ color: '#1890ff', fontSize: '16px' }}>
                        ${usdAmount.toFixed(4)}
                      </Text>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Text strong>支付 (SUI):</Text>
                      <Text strong style={{ color: '#1890ff', fontSize: '16px' }}>
                        {suiAmount.toFixed(4)} SUI
                      </Text>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Text type="secondary" style={{ fontSize: '12px' }}>支付 (MIST):</Text>
                      <Text type="secondary" style={{ fontSize: '12px' }}>
                        {suiAmountMist.toLocaleString()} MIST
                      </Text>
                    </div>
                  </Space>
                </Card>

                {/* 购买按钮 */}
                <Form.Item>
                  <Button
                    type="primary"
                    size="large"
                    block
                    icon={<WalletOutlined />}
                    onClick={handlePurchase}
                    loading={isExecuting}
                    disabled={!suiPrice || !pricingConfig || priceLoading || configLoading}
                  >
                    {isExecuting ? '交易处理中...' : '立即购买'}
                  </Button>
                </Form.Item>
              </Form>

              {/* 提示信息 */}
              <Alert
                message="购买说明"
                description={
                  <ul style={{ paddingLeft: '20px', margin: 0 }}>
                    <li>价格基于 Pyth Network 实时预言机数据</li>
                    <li>交易将自动从您的钱包扣除相应数量的 SUI</li>
                    <li>交易成功后，Token 将立即到账</li>
                    <li>
                      价格允许 {((pricingConfig?.price_tolerance || 0.05) * 100).toFixed(0)}%
                      的波动范围
                    </li>
                  </ul>
                }
                type="info"
                showIcon
              />
            </>
          )}
        </Space>
      </Card>
    </div>
  )
}
