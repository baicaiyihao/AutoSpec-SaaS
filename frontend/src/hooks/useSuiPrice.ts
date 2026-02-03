/**
 * 实时 SUI/USD 价格 Hook
 *
 * 从 Pyth Network 获取实时价格
 */
import { useState, useEffect } from 'react'
import { PYTH_API, PYTH_PRICE_FEED } from '../config/sui'

interface SuiPrice {
  price: number
  confidence: number
  expo: number
  publishTime: number
}

export function useSuiPrice(refreshInterval: number = 10000) {
  const [price, setPrice] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchPrice = async () => {
      try {
        const response = await fetch(
          `${PYTH_API}?ids[]=${PYTH_PRICE_FEED.SUI_USD}`
        )

        if (!response.ok) {
          throw new Error('Failed to fetch price')
        }

        const data = await response.json()

        if (!data || data.length === 0) {
          throw new Error('No price data available')
        }

        const priceData = data[0].price
        const rawPrice = parseFloat(priceData.price)
        const expo = parseInt(priceData.expo)

        // 计算实际价格: price * 10^expo
        const actualPrice = rawPrice * Math.pow(10, expo)

        setPrice(actualPrice)
        setError(null)
      } catch (err: any) {
        console.error('Failed to fetch SUI price:', err)
        setError(err.message || 'Failed to fetch price')
      } finally {
        setLoading(false)
      }
    }

    // 立即获取一次
    fetchPrice()

    // 定期刷新
    const interval = setInterval(fetchPrice, refreshInterval)

    return () => clearInterval(interval)
  }, [refreshInterval])

  return { price, loading, error }
}
