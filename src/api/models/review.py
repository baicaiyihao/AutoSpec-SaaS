"""
Review 相关 Pydantic 模型
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class ReviewActionTypeEnum(str, Enum):
    """Review 操作类型"""
    CONFIRM = "confirm"
    REJECT = "reject"
    DOWNGRADE = "downgrade"
    UPGRADE = "upgrade"
    ADD_NOTE = "add_note"


class SeverityEnum(str, Enum):
    """漏洞严重性"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ADVISORY = "advisory"


class ReviewSessionCreate(BaseModel):
    """创建 Review 会话请求"""
    report_id: str = Field(..., description="报告 ID")
    initial_finding_id: Optional[str] = Field(None, description="初始聚焦的漏洞 ID")


class ReviewMessage(BaseModel):
    """Review 消息"""
    id: str
    role: str  # user, assistant, system
    content: str
    metadata: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ReviewAction(BaseModel):
    """Review 操作记录"""
    id: str
    finding_id: str
    action_type: ReviewActionTypeEnum
    from_value: Optional[str]
    to_value: Optional[str]
    reason: Optional[str]
    ai_analysis: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ReviewSessionResponse(BaseModel):
    """Review 会话响应"""
    id: str
    report_id: str
    focused_finding_id: Optional[str]
    is_active: bool
    messages: List[ReviewMessage]
    actions: List[ReviewAction]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ReviewActionRequest(BaseModel):
    """Review 操作请求"""
    action_type: ReviewActionTypeEnum
    finding_id: str
    new_severity: Optional[SeverityEnum] = None  # 用于 downgrade/upgrade
    reason: Optional[str] = Field(None, description="操作理由")


class ChatRequest(BaseModel):
    """聊天请求"""
    message: str = Field(..., min_length=1, description="用户消息")
    finding_id: Optional[str] = Field(None, description="当前聚焦的漏洞 ID (可选，覆盖 session 中的 focused_finding_id)")


class ChatResponse(BaseModel):
    """聊天响应"""
    message_id: str
    content: str
    metadata: Optional[Dict[str, Any]] = None
    suggested_actions: Optional[List[str]] = None


class FocusRequest(BaseModel):
    """聚焦漏洞请求"""
    finding_id: str = Field(..., description="漏洞 ID")
