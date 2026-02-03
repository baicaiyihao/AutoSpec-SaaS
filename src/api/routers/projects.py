"""
项目管理 API 路由

v2.6.0: 支持文件夹上传
"""
import shutil
import uuid
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc)
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.project import (
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectListResponse,
)
from ..config import get_settings
from ..auth.dependencies import get_current_user
from ...storage.database import get_db, Project, Audit, User, UserRole, Blockchain


router = APIRouter(prefix="/projects", tags=["projects"])


def _count_move_files(source_path: str) -> int:
    """统计 sources/ 目录下的 Move 文件数量"""
    path = Path(source_path)
    if not path.exists():
        return 0

    # 优先在 sources/ 目录下查找
    sources_dir = path / "sources"
    if not sources_dir.exists():
        sources_dir = path

    count = 0
    for move_file in sources_dir.rglob("*.move"):
        rel_str = str(move_file.relative_to(sources_dir))
        if rel_str.startswith("build/") or "/dependencies/" in rel_str:
            continue
        count += 1
    return count


def _project_to_response(project: Project, last_audit: Optional[Audit] = None) -> ProjectResponse:
    """将 ORM 对象转换为响应模型"""
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        blockchain=project.blockchain.value if project.blockchain else None,
        source_path=project.source_path,
        file_count=project.file_count,
        created_at=project.created_at,
        updated_at=project.updated_at,
        last_audit_id=last_audit.id if last_audit else None,
        last_audit_status=last_audit.status.value if last_audit else None,
    )


def _check_owner(project: Project, user: User):
    """检查项目所有权（Admin 跳过）"""
    if user.role == UserRole.ADMIN:
        return
    if project.owner_id and project.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无权访问该项目")


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    request: ProjectCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    创建新项目

    - **name**: 项目名称
    - **description**: 项目描述（可选）
    - **source_path**: Move 项目源码路径
    """
    # 验证路径存在
    source_path = Path(request.source_path)
    if not source_path.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"源码路径不存在: {request.source_path}"
        )

    # 统计文件数量
    file_count = _count_move_files(request.source_path)
    if file_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"未找到 .move 文件: {request.source_path}"
        )

    # 创建项目
    project = Project(
        name=request.name,
        description=request.description,
        blockchain=Blockchain(request.blockchain) if request.blockchain else None,
        source_path=str(source_path.absolute()),
        file_count=file_count,
        owner_id=user.id,
    )

    db.add(project)
    await db.flush()
    await db.refresh(project)

    return _project_to_response(project)


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    skip: int = 0,
    limit: int = 20,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    获取项目列表

    - **skip**: 跳过记录数
    - **limit**: 返回记录数（最大 100）
    """
    limit = min(limit, 100)

    # 查询总数（非 Admin 只看自己的）
    count_query = select(func.count(Project.id))
    if user.role != UserRole.ADMIN:
        count_query = count_query.where(Project.owner_id == user.id)
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # 查询项目列表
    query = (
        select(Project)
        .options(selectinload(Project.audits))
        .order_by(Project.updated_at.desc())
        .offset(skip)
        .limit(limit)
    )
    if user.role != UserRole.ADMIN:
        query = query.where(Project.owner_id == user.id)
    result = await db.execute(query)
    projects = result.scalars().all()

    # 转换响应
    items = []
    for project in projects:
        # 获取最新审计
        last_audit = None
        if project.audits:
            last_audit = max(project.audits, key=lambda a: a.created_at)
        items.append(_project_to_response(project, last_audit))

    return ProjectListResponse(total=total, items=items)


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取项目详情"""
    query = (
        select(Project)
        .options(selectinload(Project.audits))
        .where(Project.id == project_id)
    )
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )
    _check_owner(project, user)

    last_audit = None
    if project.audits:
        last_audit = max(project.audits, key=lambda a: a.created_at)

    return _project_to_response(project, last_audit)


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    request: ProjectUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """更新项目信息"""
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )
    _check_owner(project, user)

    # 更新字段
    if request.name is not None:
        project.name = request.name
    if request.description is not None:
        project.description = request.description
    if request.blockchain is not None:
        project.blockchain = Blockchain(request.blockchain) if request.blockchain else None

    await db.flush()
    await db.refresh(project)

    return _project_to_response(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    删除项目

    同时删除服务器上存储的项目文件（仅限通过上传创建的项目）
    并取消该项目下的所有运行中的审计任务
    """
    query = select(Project).options(selectinload(Project.audits)).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )
    _check_owner(project, user)

    # 取消所有运行中的审计任务
    from ..services.audit_service import get_audit_service
    audit_service = get_audit_service()
    for audit in project.audits:
        if audit.status.value in ['pending', 'running']:
            if audit_service.is_running(audit.id):
                await audit_service.cancel_audit(audit.id)

    # 删除本地存储的文件（仅限 projects_dir 下的项目）
    settings = get_settings()
    source_path = Path(project.source_path)
    projects_dir = settings.projects_dir.resolve()

    try:
        # 安全检查：只删除在 projects_dir 下的目录
        if source_path.exists() and projects_dir in source_path.resolve().parents:
            shutil.rmtree(source_path, ignore_errors=True)
    except Exception as e:
        # 记录错误但不阻止数据库删除
        print(f"Warning: Failed to delete project files: {e}")

    await db.delete(project)


@router.get("/{project_id}/files")
async def list_project_files(
    project_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取项目文件列表"""
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )
    _check_owner(project, user)

    source_path = Path(project.source_path)
    if not source_path.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"源码路径不存在: {project.source_path}"
        )

    # 获取 sources/ 下所有 .move 文件 + 根目录 Move.toml
    files = []

    # sources/ 目录下的 .move 文件
    sources_dir = source_path / "sources"
    if not sources_dir.exists():
        sources_dir = source_path

    for move_file in sources_dir.rglob("*.move"):
        rel_path = move_file.relative_to(source_path)
        rel_str = str(rel_path)
        if rel_str.startswith("build/") or "/dependencies/" in rel_str:
            continue
        files.append({
            "path": rel_str,
            "name": move_file.name,
            "size": move_file.stat().st_size,
        })

    # 根目录的 Move.toml
    toml_file = source_path / "Move.toml"
    if toml_file.exists():
        files.append({
            "path": "Move.toml",
            "name": "Move.toml",
            "size": toml_file.stat().st_size,
        })

    return {
        "project_id": project_id,
        "source_path": project.source_path,
        "total": len(files),
        "files": sorted(files, key=lambda f: f["path"])
    }


@router.get("/{project_id}/files/{file_path:path}")
async def get_project_file(
    project_id: str,
    file_path: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取项目文件内容"""
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )
    _check_owner(project, user)

    source_path = Path(project.source_path)
    full_path = source_path / file_path

    # 安全检查：确保路径在项目目录内
    try:
        full_path.resolve().relative_to(source_path.resolve())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="非法文件路径"
        )

    if not full_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"文件不存在: {file_path}"
        )

    content = full_path.read_text(encoding="utf-8")

    return {
        "project_id": project_id,
        "file_path": file_path,
        "content": content,
        "size": len(content),
    }


@router.post("/upload", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def upload_project(
    name: str = Form(..., description="项目名称"),
    description: Optional[str] = Form(None, description="项目描述"),
    blockchain: Optional[str] = Form(None, description="所属区块链"),
    files: List[UploadFile] = File(..., description="Move 文件列表"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    上传项目文件

    接收多个文件，自动保存到服务器并创建项目。
    前端应使用 webkitdirectory 属性让用户选择文件夹。

    - **name**: 项目名称
    - **description**: 项目描述（可选）
    - **blockchain**: 所属区块链 (sui)
    - **files**: Move 文件列表（包含相对路径）
    """
    settings = get_settings()

    # 创建项目目录
    project_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    project_dir = settings.projects_dir / f"{name}_{timestamp}_{project_id[:8]}"
    project_dir.mkdir(parents=True, exist_ok=True)

    move_file_count = 0

    try:
        for upload_file in files:
            # 获取相对路径（前端通过 webkitRelativePath 传递）
            # 文件名格式: "folder/sources/module.move" 或 "folder/Move.toml"
            filename = upload_file.filename or "unknown"

            # 移除开头的目录名（用户选择的文件夹名）
            path_parts = Path(filename).parts
            if len(path_parts) > 1:
                rel_path = Path(*path_parts[1:])
            else:
                rel_path = Path(filename)

            rel_str = str(rel_path)

            # 只保留 sources/ 下的 .move 文件 和 根目录 Move.toml
            is_sources_move = (
                rel_str.startswith("sources/") and
                filename.endswith(".move") and
                "/build/" not in rel_str and
                "/dependencies/" not in rel_str
            )
            is_root_toml = (rel_str == "Move.toml")

            if not (is_sources_move or is_root_toml):
                continue

            # 确保目标目录存在
            target_path = project_dir / rel_path
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # 保存文件
            content = await upload_file.read()
            target_path.write_bytes(content)
            if is_sources_move:
                move_file_count += 1

        if move_file_count == 0:
            # 清理并报错
            shutil.rmtree(project_dir, ignore_errors=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="未找到 sources/ 目录下的 .move 文件，请确保上传的是 Move 项目"
            )

        # 创建项目记录
        project = Project(
            id=project_id,
            name=name,
            description=description,
            blockchain=Blockchain(blockchain) if blockchain else None,
            source_path=str(project_dir.absolute()),
            file_count=move_file_count,
            owner_id=user.id,
        )

        db.add(project)
        await db.flush()
        await db.refresh(project)

        return _project_to_response(project)

    except HTTPException:
        raise
    except Exception as e:
        # 清理并报错
        shutil.rmtree(project_dir, ignore_errors=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"上传失败: {str(e)}"
        )


class ReimportPathRequest(BaseModel):
    source_path: str


@router.post("/{project_id}/reimport", response_model=ProjectResponse)
async def reimport_project(
    project_id: str,
    files: List[UploadFile] = File(..., description="Move 文件列表"),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    重新导入项目文件（上传方式）

    替换已有文件，保留项目元信息。
    只保留 sources/ 下的 .move 文件和根目录 Move.toml。
    """
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )
    _check_owner(project, user)

    settings = get_settings()
    source_path = Path(project.source_path)
    projects_dir = settings.projects_dir.resolve()

    # 安全检查：只允许清空 projects_dir 下的目录
    is_managed = source_path.exists() and projects_dir in source_path.resolve().parents
    if not is_managed:
        # 对于本地路径项目，创建一个新的托管目录
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        source_path = settings.projects_dir / f"{project.name}_{timestamp}_{project_id[:8]}"
        source_path.mkdir(parents=True, exist_ok=True)
        project.source_path = str(source_path.absolute())
    else:
        # 清空已有文件
        shutil.rmtree(source_path, ignore_errors=True)
        source_path.mkdir(parents=True, exist_ok=True)

    move_file_count = 0

    try:
        for upload_file in files:
            filename = upload_file.filename or "unknown"

            # 移除开头的目录名
            path_parts = Path(filename).parts
            if len(path_parts) > 1:
                rel_path = Path(*path_parts[1:])
            else:
                rel_path = Path(filename)

            rel_str = str(rel_path)

            # 只保留 sources/ 下的 .move 文件 和 根目录 Move.toml
            is_sources_move = (
                rel_str.startswith("sources/") and
                filename.endswith(".move") and
                "/build/" not in rel_str and
                "/dependencies/" not in rel_str
            )
            is_root_toml = (rel_str == "Move.toml")

            if not (is_sources_move or is_root_toml):
                continue

            target_path = source_path / rel_path
            target_path.parent.mkdir(parents=True, exist_ok=True)

            content = await upload_file.read()
            target_path.write_bytes(content)
            if is_sources_move:
                move_file_count += 1

        if move_file_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="未找到 sources/ 目录下的 .move 文件"
            )

        project.file_count = move_file_count
        project.updated_at = utc_now()
        await db.flush()
        await db.refresh(project)

        return _project_to_response(project)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"重新导入失败: {str(e)}"
        )


@router.post("/{project_id}/reimport-path", response_model=ProjectResponse)
async def reimport_project_by_path(
    project_id: str,
    request: ReimportPathRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    通过本地路径重新导入项目

    更新 source_path 并重新统计文件数。
    """
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )
    _check_owner(project, user)

    new_path = Path(request.source_path)
    if not new_path.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"源码路径不存在: {request.source_path}"
        )

    file_count = _count_move_files(request.source_path)
    if file_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"未找到 sources/ 目录下的 .move 文件: {request.source_path}"
        )

    project.source_path = str(new_path.absolute())
    project.file_count = file_count
    project.updated_at = utc_now()
    await db.flush()
    await db.refresh(project)

    return _project_to_response(project)
