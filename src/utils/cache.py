"""
分析结果缓存

避免相同代码重复分析，提升大型项目（如 Cetus）审计效率。
支持内存 + 磁盘双层缓存。
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional


class AnalysisCache:
    """分析结果缓存"""

    def __init__(self, cache_dir: str = "data/cache", ttl: int = 86400):
        """
        Args:
            cache_dir: 缓存目录
            ttl: 缓存有效期（秒），默认 24 小时
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self.memory_cache: Dict[str, Any] = {}

    def _hash_key(self, key: str) -> str:
        """生成缓存键的哈希"""
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _get_cache_path(self, key_hash: str) -> Path:
        """获取缓存文件路径"""
        return self.cache_dir / f"{key_hash}.json"

    def get(self, key: str) -> Optional[Any]:
        """
        获取缓存

        Args:
            key: 缓存键（通常是代码的哈希或唯一标识）

        Returns:
            缓存的值，如果不存在或已过期返回 None
        """
        key_hash = self._hash_key(key)

        # 先检查内存缓存
        if key_hash in self.memory_cache:
            entry = self.memory_cache[key_hash]
            if time.time() - entry["timestamp"] < self.ttl:
                return entry["value"]
            else:
                del self.memory_cache[key_hash]

        # 检查磁盘缓存
        cache_path = self._get_cache_path(key_hash)
        if cache_path.exists():
            try:
                with open(cache_path, "r") as f:
                    entry = json.load(f)
                if time.time() - entry["timestamp"] < self.ttl:
                    # 加载到内存缓存
                    self.memory_cache[key_hash] = entry
                    return entry["value"]
                else:
                    # 已过期，删除
                    cache_path.unlink()
            except Exception:
                pass

        return None

    def set(self, key: str, value: Any) -> None:
        """
        设置缓存

        Args:
            key: 缓存键
            value: 缓存值（必须可 JSON 序列化）
        """
        key_hash = self._hash_key(key)
        entry = {
            "timestamp": time.time(),
            "value": value
        }

        # 写入内存缓存
        self.memory_cache[key_hash] = entry

        # 写入磁盘缓存
        cache_path = self._get_cache_path(key_hash)
        try:
            with open(cache_path, "w") as f:
                json.dump(entry, f)
        except Exception:
            pass

    def invalidate(self, key: str) -> None:
        """使缓存失效"""
        key_hash = self._hash_key(key)

        if key_hash in self.memory_cache:
            del self.memory_cache[key_hash]

        cache_path = self._get_cache_path(key_hash)
        if cache_path.exists():
            cache_path.unlink()

    def clear(self) -> None:
        """清空所有缓存"""
        self.memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()


# 全局缓存实例
analysis_cache = AnalysisCache()


def cache_key_for_code(code: str, analysis_type: str) -> str:
    """为代码生成缓存键"""
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:32]
    return f"{analysis_type}:{code_hash}"
