"""
密码强度验证模块
"""
import re
from typing import Tuple, List


def validate_password_strength(password: str, min_length: int = 8) -> Tuple[bool, List[str]]:
    """验证密码强度

    Args:
        password: 用户输入的密码
        min_length: 最小长度要求（默认8）

    Returns:
        (is_valid, errors): 是否有效 + 错误列表
    """
    errors: List[str] = []

    # 1. 长度检查
    if len(password) < min_length:
        errors.append(f"密码长度至少{min_length}位")

    # 2. 大小写字母
    if not re.search(r"[a-z]", password):
        errors.append("密码需包含小写字母")
    if not re.search(r"[A-Z]", password):
        errors.append("密码需包含大写字母")

    # 3. 数字
    if not re.search(r"\d", password):
        errors.append("密码需包含数字")

    # 4. 特殊字符（可选）
    # if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
    #     errors.append("密码需包含特殊字符")

    return len(errors) == 0, errors


def get_password_strength_level(password: str) -> str:
    """获取密码强度等级

    Returns:
        'weak' | 'medium' | 'strong'
    """
    score = 0

    # 长度
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    # 字符类型
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 1

    if score <= 2:
        return "weak"
    elif score <= 3:
        return "medium"
    else:
        return "strong"
