"""
项目相关 Pydantic 模型
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    """创建项目请求"""
    name: str = Field(..., min_length=1, max_length=255, description="项目名称")
    description: Optional[str] = Field(None, description="项目描述")
    source_path: str = Field(..., description="Move 项目路径")
    blockchain: Optional[str] = Field(None, description="所属区块链 (sui)")


class ProjectUpdate(BaseModel):
    """更新项目请求"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    blockchain: Optional[str] = Field(None, description="所属区块链")


class ProjectResponse(BaseModel):
    """项目响应"""
    id: str
    name: str
    description: Optional[str]
    blockchain: Optional[str]
    source_path: str
    file_count: int
    created_at: datetime
    updated_at: datetime
    last_audit_id: Optional[str] = None
    last_audit_status: Optional[str] = None

    class Config:
        from_attributes = True


class ProjectListResponse(BaseModel):
    """项目列表响应"""
    total: int
    items: List[ProjectResponse]
