"""
Token 充值服务 (v2 with Pyth integration)

负责：
1. 验证链上交易
2. 解析 PurchaseEvent 事件
3. 更新用户 Token 余额
4. 记录充值历史

注意：价格验证已由智能合约通过 Pyth 预言机完成，后端无需再验证价格
"""
import httpx
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ...storage.database import User, TokenPurchase, TokenPurchaseStatus, generate_uuid


class TokenPurchaseService:
    """Token 充值服务"""

    def __init__(
        self,
        sui_rpc_url: str,
        package_id: str,
        price_tolerance: float = 0.05  # 价格容差 5%
    ):
        """
        初始化服务

        Args:
            sui_rpc_url: Sui RPC 节点 URL
            package_id: 智能合约 Package ID
            price_tolerance: 价格容差（默认 5%）
        """
        self.sui_rpc_url = sui_rpc_url
        self.package_id = package_id
        self.price_tolerance = price_tolerance

    async def verify_and_process_purchase(
        self,
        db: AsyncSession,
        transaction_digest: str,
        user_id: str,
    ) -> Dict[str, Any]:
        """
        验证交易并处理充值

        Args:
            db: 数据库会话
            transaction_digest: 交易哈希
            user_id: 用户 ID

        Returns:
            处理结果

        Raises:
            ValueError: 交易验证失败
        """
        # 1. 检查是否已处理
        result = await db.execute(
            select(TokenPurchase).where(
                TokenPurchase.transaction_digest == transaction_digest
            )
        )
        existing_purchase = result.scalar_one_or_none()

        if existing_purchase:
            if existing_purchase.status == TokenPurchaseStatus.CONFIRMED:
                return {
                    "status": "already_processed",
                    "purchase_id": existing_purchase.id,
                    "message": "该交易已处理"
                }
            elif existing_purchase.status == TokenPurchaseStatus.FAILED:
                raise ValueError(f"交易已标记为失败: {existing_purchase.error_message}")

        # 2. 获取交易详情
        txn_data = await self._get_transaction(transaction_digest)

        # 3. 验证交易成功
        if not self._is_transaction_successful(txn_data):
            raise ValueError("交易未成功执行")

        # 4. 解析 PurchaseEvent
        event_data = self._parse_purchase_event(txn_data)
        if not event_data:
            raise ValueError("未找到 PurchaseEvent 事件")

        # 5. 验证买家地址
        buyer_address = event_data["buyer"]

        # 查询用户钱包地址
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError("用户不存在")

        if not user.wallet_address:
            raise ValueError("用户未绑定钱包")

        if buyer_address.lower() != user.wallet_address.lower():
            raise ValueError(f"交易买家地址与用户钱包不匹配: {buyer_address} != {user.wallet_address}")

        # 6. 提取事件数据
        # 注意：价格验证已由智能合约通过 Pyth 预言机完成，无需后端再验证
        sui_amount_mist = event_data["sui_amount"]
        usd_amount_cents = event_data["usd_amount"]
        token_amount = event_data["token_amount"]

        # 计算价格（仅用于记录）
        sui_usd_price = (usd_amount_cents / 100) / (sui_amount_mist / 1e9) if sui_amount_mist > 0 else 0
        token_usd_price = (usd_amount_cents / 100) / token_amount if token_amount > 0 else 0

        # 7. 充值成功，更新用户余额
        user.token_balance += token_amount

        purchase = TokenPurchase(
            id=generate_uuid(),
            user_id=user_id,
            transaction_digest=transaction_digest,
            wallet_address=buyer_address.lower(),
            sui_amount=sui_amount_mist,
            usd_amount=usd_amount_cents,
            sui_usd_price=sui_usd_price,
            token_amount=token_amount,
            token_usd_price=token_usd_price,
            status=TokenPurchaseStatus.CONFIRMED,
            blockchain_timestamp=datetime.fromtimestamp(
                event_data["timestamp"] / 1000, tz=timezone.utc
            ),
            confirmed_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        db.add(purchase)
        await db.commit()

        return {
            "status": "success",
            "purchase_id": purchase.id,
            "token_amount": token_amount,
            "new_balance": user.token_balance,
            "message": f"充值成功！获得 {token_amount} Token"
        }

    async def _get_transaction(self, digest: str) -> Dict[str, Any]:
        """
        获取交易详情

        Args:
            digest: 交易哈希

        Returns:
            交易数据
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self.sui_rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "sui_getTransactionBlock",
                    "params": [
                        digest,
                        {
                            "showInput": True,
                            "showEffects": True,
                            "showEvents": True,
                            "showObjectChanges": False,
                            "showBalanceChanges": False,
                        }
                    ]
                }
            )
            response.raise_for_status()
            data = response.json()

            if "error" in data:
                raise ValueError(f"RPC 错误: {data['error']}")

            return data["result"]

    def _is_transaction_successful(self, txn_data: Dict[str, Any]) -> bool:
        """
        检查交易是否成功

        Args:
            txn_data: 交易数据

        Returns:
            是否成功
        """
        effects = txn_data.get("effects", {})
        status = effects.get("status", {})
        return status.get("status") == "success"

    def _parse_purchase_event(self, txn_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        解析 PurchaseEvent 事件

        Args:
            txn_data: 交易数据

        Returns:
            事件数据或 None
        """
        events = txn_data.get("events", [])

        for event in events:
            # 检查事件类型
            event_type = event.get("type", "")
            if f"{self.package_id}::token_purchase::PurchaseEvent" in event_type:
                parsed_json = event.get("parsedJson", {})
                return {
                    "buyer": parsed_json.get("buyer"),
                    "sui_amount": int(parsed_json.get("sui_amount", 0)),
                    "usd_amount": int(parsed_json.get("usd_amount", 0)),
                    "token_amount": int(parsed_json.get("token_amount", 0)),
                    "timestamp": int(parsed_json.get("timestamp", 0)),
                }

        return None

    async def _get_sui_usd_price(self) -> float:
        """
        从 Pyth Network 获取实时 SUI/USD 价格

        Returns:
            SUI/USD 价格
        """
        # Pyth Price Service API (HTTP)
        # SUI/USD Price Feed ID: 0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744
        price_feed_id = "0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744"

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://hermes.pyth.network/api/latest_price_feeds?ids[]={price_feed_id}"
            )
            response.raise_for_status()
            data = response.json()

            if not data or len(data) == 0:
                raise ValueError("无法获取 SUI/USD 价格")

            price_data = data[0]["price"]
            price = float(price_data["price"])
            expo = int(price_data["expo"])

            # price * 10^expo
            return price * (10 ** expo)
