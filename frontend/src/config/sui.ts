/**
 * Sui 区块链配置
 */

// 智能合约地址（Testnet）- v3 with Pyth + 修复计算精度
export const SUI_CONTRACT = {
  PACKAGE_ID: '0x6583b831557dfe2e264f64754bae513006e15323a0131f2b028b2b4e37f710a6',
  ADMIN_CAP_ID: '0x372c668c319ddd7c43b10bd201037989878b154d8f2c1ce8e9fa74b22ae9169f',
  SUI_POOL_ID: '0x891d18976bc5184eee6dc794ace92e591cf85ceb0efa34affa185945488e27bd',
  CLOCK_ID: '0x6', // Sui 系统时钟（固定）
  // Pyth State (Testnet) - from Fate3AI
  PYTH_STATE: '0x243759059f4c3111179da5878c12f68d612c21a8d54d85edc86164bb18be1c7c',
} as const

// Pyth Network Price Feed ID
export const PYTH_PRICE_FEED = {
  // SUI/USD Price Feed ID (from Fate3AI) - same for testnet
  SUI_USD: '0x50c67b3fd225db8912a424dd4baed60ffdde625ed2feaaf283724f9608fea266',
} as const

// Pyth Wormhole State ID (Testnet)
export const PYTH_WORMHOLE_STATE = '0x31358d198147da50db32eda2562951d53973a0c0ad5ed738e9b17d88b213d790' as const

// Pyth Price Service API (Beta for Testnet)
export const PYTH_API = 'https://hermes-beta.pyth.network/api/latest_price_feeds'

// Sui 网络配置
export const SUI_NETWORK = import.meta.env.VITE_SUI_NETWORK || 'testnet'

// RPC URLs
export const SUI_RPC_URLS = {
  testnet: 'https://fullnode.testnet.sui.io:443',
  mainnet: 'https://fullnode.mainnet.sui.io:443',
  devnet: 'https://fullnode.devnet.sui.io:443',
} as const

// 单位转换
export const SUI_UNITS = {
  MIST_PER_SUI: 1_000_000_000, // 1 SUI = 10^9 MIST
  CENTS_PER_USD: 100,           // 1 USD = 100 cents
} as const
