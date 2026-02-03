"""
为 Sui Token 充值系统添加系统配置

在 system_settings 表中添加 Sui 相关配置项
"""
import asyncio
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import select
from src.storage.database import _get_session_factory, SystemSettings


async def seed_sui_settings():
    """添加 Sui 系统配置"""
    session_factory = _get_session_factory()

    async with session_factory() as session:
        print("🔄 添加 Sui 系统配置...")

        # 配置项定义
        settings = [
            # Sui 网络配置
            {
                "key": "sui_rpc_url",
                "value": "https://fullnode.testnet.sui.io:443",
                "value_type": "string",
                "category": "sui",
                "description": "Sui RPC 节点 URL（testnet 或 mainnet）",
            },
            {
                "key": "sui_package_id",
                "value": "",
                "value_type": "string",
                "category": "sui",
                "description": "智能合约 Package ID（部署后填写）",
            },
            {
                "key": "sui_pool_id",
                "value": "",
                "value_type": "string",
                "category": "sui",
                "description": "SuiPool 共享对象 ID（部署后填写）",
            },
            {
                "key": "sui_admin_cap_id",
                "value": "",
                "value_type": "string",
                "category": "sui",
                "description": "AdminCap 对象 ID（部署后填写）",
            },
            # 价格配置
            {
                "key": "sui_price_tolerance",
                "value": "0.05",
                "value_type": "float",
                "category": "sui",
                "description": "价格容差（0.05 = 5%）",
            },
            {
                "key": "token_usd_price",
                "value": "0.01",
                "value_type": "float",
                "category": "pricing",
                "description": "Token 单价（USD per Token）",
            },
            {
                "key": "service_fee_markup",
                "value": "2.0",
                "value_type": "float",
                "category": "pricing",
                "description": "服务费倍数（2.0 = LLM 成本 × 2）",
            },
            # LLM 成本配置（美元/100万 tokens）
            {
                "key": "llm_cost_qwen_turbo",
                "value": "0.30",
                "value_type": "float",
                "category": "pricing",
                "description": "Qwen-Turbo 成本（USD/1M tokens）",
            },
            {
                "key": "llm_cost_qwen_plus",
                "value": "0.56",
                "value_type": "float",
                "category": "pricing",
                "description": "Qwen-Plus 成本（USD/1M tokens）",
            },
            {
                "key": "llm_cost_qwen_max",
                "value": "5.60",
                "value_type": "float",
                "category": "pricing",
                "description": "Qwen-Max 成本（USD/1M tokens）",
            },
            {
                "key": "llm_cost_deepseek_chat",
                "value": "0.14",
                "value_type": "float",
                "category": "pricing",
                "description": "DeepSeek-Chat 成本（USD/1M tokens）",
            },
            {
                "key": "llm_cost_deepseek_reasoner",
                "value": "0.55",
                "value_type": "float",
                "category": "pricing",
                "description": "DeepSeek-Reasoner 成本（USD/1M tokens）",
            },
            {
                "key": "llm_cost_glm4_flash",
                "value": "0.01",
                "value_type": "float",
                "category": "pricing",
                "description": "GLM-4-Flash 成本（USD/1M tokens）",
            },
            {
                "key": "llm_cost_claude_haiku",
                "value": "0.80",
                "value_type": "float",
                "category": "pricing",
                "description": "Claude-3.5-Haiku 成本（USD/1M tokens）",
            },
            {
                "key": "llm_cost_claude_sonnet",
                "value": "3.00",
                "value_type": "float",
                "category": "pricing",
                "description": "Claude-3.5-Sonnet 成本（USD/1M tokens）",
            },
        ]

        # 插入或更新配置
        for setting in settings:
            result = await session.execute(
                select(SystemSettings).where(SystemSettings.key == setting["key"])
            )
            existing = result.scalar_one_or_none()

            if existing:
                print(f"  ⚠️  {setting['key']} 已存在，跳过")
            else:
                new_setting = SystemSettings(**setting)
                session.add(new_setting)
                print(f"  ✅ 添加 {setting['key']}")

        await session.commit()
        print("\n✅ Sui 系统配置添加完成！")


if __name__ == "__main__":
    print("=" * 60)
    print("Sui 系统配置种子数据")
    print("=" * 60)
    asyncio.run(seed_sui_settings())
