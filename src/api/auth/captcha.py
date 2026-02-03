"""
验证码生成与验证模块
"""
import io
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional

from captcha.image import ImageCaptcha


class CaptchaStore:
    """内存验证码存储（生产环境建议用 Redis）"""

    def __init__(self, expire_minutes: int = 5):
        self._store: Dict[str, tuple[str, datetime]] = {}  # {captcha_id: (code, expire_time)}
        self.expire_minutes = expire_minutes

    def generate(self, length: int = 4) -> tuple[str, str]:
        """生成验证码

        Returns:
            (captcha_id, code): 验证码ID和验证码文本
        """
        # 清理过期验证码
        self._cleanup()

        captcha_id = secrets.token_urlsafe(16)
        code = self._generate_code(length)
        expire_time = datetime.utcnow() + timedelta(minutes=self.expire_minutes)

        self._store[captcha_id] = (code, expire_time)
        return captcha_id, code

    def verify(self, captcha_id: str, code: str) -> bool:
        """验证验证码（不区分大小写）

        Args:
            captcha_id: 验证码ID
            code: 用户输入的验证码

        Returns:
            bool: 验证是否成功
        """
        if captcha_id not in self._store:
            return False

        stored_code, expire_time = self._store[captcha_id]

        # 验证后立即删除（一次性）
        del self._store[captcha_id]

        # 检查是否过期
        if datetime.utcnow() > expire_time:
            return False

        # 不区分大小写
        return stored_code.lower() == code.lower()

    def _generate_code(self, length: int) -> str:
        """生成随机验证码（大写字母+数字，排除易混淆字符）"""
        # 排除 0O1Il 等易混淆字符
        chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        return "".join(secrets.choice(chars) for _ in range(length))

    def _cleanup(self):
        """清理过期验证码"""
        now = datetime.utcnow()
        expired_keys = [
            captcha_id
            for captcha_id, (_, expire_time) in self._store.items()
            if now > expire_time
        ]
        for key in expired_keys:
            del self._store[key]


# 全局验证码存储实例
captcha_store = CaptchaStore()


def generate_captcha_image(code: str, width: int = 160, height: int = 60) -> bytes:
    """生成验证码图片

    Args:
        code: 验证码文本
        width: 图片宽度
        height: 图片高度

    Returns:
        bytes: PNG 图片二进制数据
    """
    image = ImageCaptcha(width=width, height=height)
    image_data = image.generate(code)

    # 转换为 bytes
    buf = io.BytesIO()
    buf.write(image_data.read())
    buf.seek(0)
    return buf.getvalue()
