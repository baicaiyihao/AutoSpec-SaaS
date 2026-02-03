"""API Key 加密存储"""
import json
from cryptography.fernet import Fernet
from ..config import get_settings

# 备用密钥（当未配置时使用，生产环境应通过 env 配置）
_FALLBACK_KEY = b'ZmFsbGJhY2sta2V5LWZvci1kZXYtb25seS0xMjM0NTY3OA=='


def _get_fernet() -> Fernet:
    settings = get_settings()
    key = settings.api_keys_encryption_key
    if key:
        # 确保是有效的 Fernet key
        return Fernet(key.encode() if isinstance(key, str) else key)
    # Dev fallback - 生成一个固定 key
    return Fernet(Fernet.generate_key())


# 缓存 fernet 实例
_fernet_instance = None


def _get_cached_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        settings = get_settings()
        key = settings.api_keys_encryption_key
        if key:
            _fernet_instance = Fernet(key.encode() if isinstance(key, str) else key)
        else:
            # 生成并缓存一个 key（进程生命周期内有效）
            _fernet_instance = Fernet(Fernet.generate_key())
    return _fernet_instance


def encrypt_api_keys(keys: dict) -> str:
    """加密 API keys dict 为字符串"""
    f = _get_cached_fernet()
    plaintext = json.dumps(keys).encode()
    return f.encrypt(plaintext).decode()


def decrypt_api_keys(encrypted: str) -> dict:
    """解密 API keys 字符串为 dict"""
    if not encrypted:
        return {}
    f = _get_cached_fernet()
    try:
        plaintext = f.decrypt(encrypted.encode())
        return json.loads(plaintext)
    except Exception:
        return {}
