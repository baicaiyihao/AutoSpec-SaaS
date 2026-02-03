"""
Sui 钱包签名验证

实现基于 Ed25519 签名的钱包登录：
1. 生成挑战消息（nonce + timestamp）
2. 验证签名
3. 登录或绑定钱包
"""
import time
import secrets
import base64
from typing import Optional
from pydantic import BaseModel, Field


class WalletChallenge(BaseModel):
    """钱包挑战消息"""
    message: str = Field(..., description="需要签名的消息")
    nonce: str = Field(..., description="随机数")
    expires_at: int = Field(..., description="过期时间戳（秒）")


class WalletVerifyRequest(BaseModel):
    """钱包签名验证请求"""
    wallet_address: str = Field(..., description="钱包地址（0x + 64 hex）")
    signature: str = Field(..., description="签名（hex）")
    message: str = Field(..., description="签名的消息")
    public_key: str = Field(..., description="公钥（hex，32 bytes）")


class WalletBindRequest(BaseModel):
    """钱包绑定请求"""
    wallet_address: str = Field(..., description="钱包地址（0x + 64 hex）")
    signature: str = Field(..., description="签名（hex）")
    message: str = Field(..., description="签名的消息")
    public_key: str = Field(..., description="公钥（hex，32 bytes）")


# ============================================================================
# 挑战消息生成
# ============================================================================

def generate_challenge(wallet_address: str, ttl_seconds: int = 300) -> WalletChallenge:
    """
    生成钱包签名挑战

    Args:
        wallet_address: 钱包地址
        ttl_seconds: 有效期（秒），默认 5 分钟

    Returns:
        WalletChallenge: 挑战消息对象
    """
    nonce = secrets.token_hex(16)
    timestamp = int(time.time())
    expires_at = timestamp + ttl_seconds

    message = f"AutoSpec 登录验证\n\n钱包地址: {wallet_address}\n随机数: {nonce}\n时间: {timestamp}"

    return WalletChallenge(
        message=message,
        nonce=nonce,
        expires_at=expires_at
    )


# ============================================================================
# 签名验证
# ============================================================================

def verify_wallet_signature(
    message: str,
    signature_hex: str,
    public_key_hex: str,
    wallet_address: str,
) -> bool:
    """
    验证 Sui 钱包签名（使用 pysui SDK）

    Args:
        message: 原始消息
        signature_hex: 签名（hex 编码，64 bytes Ed25519 签名）
        public_key_hex: 公钥（hex 编码，32 bytes）
        wallet_address: 钱包地址（用于验证公钥匹配）

    Returns:
        bool: 签名是否有效

    Raises:
        ValueError: 公钥或签名格式错误
    """
    import logging
    from pysui.sui.sui_crypto import SuiPublicKey, SignatureScheme

    logger = logging.getLogger(__name__)

    try:
        # 解码公钥和签名
        public_key_bytes = bytes.fromhex(public_key_hex.replace("0x", ""))
        signature_bytes = bytes.fromhex(signature_hex.replace("0x", ""))

        if len(public_key_bytes) != 32:
            raise ValueError(f"公钥长度错误: {len(public_key_bytes)} bytes (expected 32)")
        if len(signature_bytes) != 64:
            raise ValueError(f"签名长度错误: {len(signature_bytes)} bytes (expected 64)")

        logger.info(f"🔍 签名验证调试:")
        logger.info(f"- wallet_address: {wallet_address}")
        logger.info(f"- public_key_hex: {public_key_hex}")
        logger.info(f"- signature_hex: {signature_hex}")

        # 验证公钥匹配钱包地址
        derived_address = derive_sui_address(public_key_bytes)
        logger.info(f"- derived_address: {derived_address}")

        if derived_address.lower() != wallet_address.lower():
            raise ValueError(f"公钥不匹配钱包地址: {derived_address} != {wallet_address}")

        # 🔥 使用 pysui 验证签名
        # 1. 构建 Sui 格式的完整签名（scheme + signature + pubkey）
        scheme_byte = bytes([SignatureScheme.ED25519.value])  # 0x00
        full_signature = scheme_byte + signature_bytes + public_key_bytes

        # 2. 转为 base64（pysui 格式）
        full_signature_b64 = base64.b64encode(full_signature).decode()
        message_b64 = base64.b64encode(message.encode('utf-8')).decode()

        # 3. 从序列化的公钥创建 SuiPublicKey
        # pysui 的公钥序列化格式：scheme flag + public key bytes
        serialized_pubkey = scheme_byte + public_key_bytes
        serialized_pubkey_b64 = base64.b64encode(serialized_pubkey).decode()

        sui_pub_key = SuiPublicKey.from_serialized(serialized_pubkey_b64)

        # 4. 验证签名
        is_valid = sui_pub_key.verify_personal_message(message_b64, full_signature_b64)

        if is_valid:
            logger.info("✅ 签名验证成功")
        else:
            logger.error("❌ 签名验证失败")

        return is_valid

    except Exception as e:
        logger.error(f"❌ 签名验证错误: {str(e)}")
        raise ValueError(f"签名验证错误: {str(e)}")


def derive_sui_address(public_key_bytes: bytes) -> str:
    """
    从公钥推导 Sui 地址

    Sui 地址 = Blake2b(flag || public_key)[0:32]
    其中 flag = 0x00 (Ed25519)

    Args:
        public_key_bytes: 公钥字节（32 bytes）

    Returns:
        str: Sui 地址（0x + 64 hex）
    """
    import hashlib

    # Sui 使用 Blake2b-256
    # flag = 0x00 表示 Ed25519 签名方案
    flag = b'\x00'
    hash_input = flag + public_key_bytes

    # Blake2b-256 哈希
    hasher = hashlib.blake2b(hash_input, digest_size=32)
    address_bytes = hasher.digest()

    return "0x" + address_bytes.hex()


# ============================================================================
# 挑战验证
# ============================================================================

def validate_challenge_message(message: str, wallet_address: str, max_age_seconds: int = 300) -> bool:
    """
    验证挑战消息是否有效

    Args:
        message: 挑战消息
        wallet_address: 钱包地址
        max_age_seconds: 最大有效期（秒）

    Returns:
        bool: 消息是否有效
    """
    try:
        # 解析消息
        lines = message.split('\n')
        parsed_address = None
        parsed_timestamp = None

        for line in lines:
            if line.startswith('钱包地址:'):
                parsed_address = line.split(':', 1)[1].strip()
            elif line.startswith('时间:'):
                parsed_timestamp = int(line.split(':', 1)[1].strip())

        # 验证地址匹配
        if not parsed_address or parsed_address.lower() != wallet_address.lower():
            return False

        # 验证时间戳
        if not parsed_timestamp:
            return False

        current_time = int(time.time())
        age = current_time - parsed_timestamp

        if age < 0 or age > max_age_seconds:
            return False

        return True

    except Exception:
        return False
