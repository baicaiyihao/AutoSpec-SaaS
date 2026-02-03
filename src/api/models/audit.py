"""
审计相关 Pydantic 模型
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class AuditStatusEnum(str, Enum):
    """审计状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditConfig(BaseModel):
    """审计配置"""
    enable_pattern_scan: bool = Field(True, description="启用模式扫描")
    soft_filter_mode: bool = Field(True, description="软过滤模式")
    max_functions: Optional[int] = Field(None, description="最大函数数量限制")
    target_functions: Optional[List[str]] = Field(None, description="指定审计函数")


class AuditProgress(BaseModel):
    """审计进度"""
    current_phase: int = Field(0, description="当前阶段 (0-5)")
    phase_name: str = Field("", description="阶段名称")
    progress_percent: float = Field(0.0, description="进度百分比")
    current_function: Optional[str] = Field(None, description="当前处理函数")
    total_functions: int = Field(0, description="总函数数")
    processed_functions: int = Field(0, description="已处理函数数")
    findings_count: int = Field(0, description="已发现漏洞数")
    messages: List[str] = Field(default_factory=list, description="进度消息")


class AuditCreate(BaseModel):
    """创建审计任务请求"""
    project_id: str = Field(..., description="项目 ID")
    config: Optional[AuditConfig] = Field(default_factory=AuditConfig)


class AuditResponse(BaseModel):
    """审计任务响应"""
    id: str
    project_id: str
    project_name: str
    status: AuditStatusEnum
    config: Dict[str, Any]
    progress: Optional[AuditProgress]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    report_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class AuditListResponse(BaseModel):
    """审计任务列表响应"""
    total: int
    items: List[AuditResponse]
