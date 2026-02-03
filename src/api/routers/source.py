"""
源代码查看 API 路由

提供项目源代码文件的读取、目录浏览等功能，支持代码审计视图
"""
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...storage.database import get_db, Project


router = APIRouter(prefix="/source", tags=["source"])


class FileInfo(BaseModel):
    """文件信息"""
    name: str
    path: str  # 相对于项目根目录的路径
    type: str  # 'file' 或 'directory'
    extension: Optional[str] = None
    size: Optional[int] = None


class DirectoryResponse(BaseModel):
    """目录内容响应"""
    project_id: str
    project_name: str
    current_path: str
    items: List[FileInfo]


class FileContentResponse(BaseModel):
    """文件内容响应"""
    project_id: str
    file_path: str
    file_name: str
    content: str
    language: str
    line_count: int


class CodeLocation(BaseModel):
    """代码位置"""
    file_path: str
    line_start: int
    line_end: int
    module_name: Optional[str] = None
    function_name: Optional[str] = None


class SearchResult(BaseModel):
    """搜索结果"""
    file_path: str
    line_number: int
    line_content: str
    match_start: int
    match_end: int


class SearchResponse(BaseModel):
    """搜索响应"""
    project_id: str
    query: str
    total: int
    results: List[SearchResult]


def _get_language(file_path: str) -> str:
    """根据文件扩展名获取语言类型"""
    ext_map = {
        '.move': 'move',
        '.rs': 'rust',
        '.toml': 'toml',
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.md': 'markdown',
        '.txt': 'plaintext',
    }
    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext, 'plaintext')


def _is_allowed_file(file_path: Path) -> bool:
    """检查文件是否允许访问"""
    # 排除的目录和文件模式
    excluded_dirs = {'build', 'node_modules', '.git', '__pycache__', 'target'}
    excluded_patterns = {'.pyc', '.pyo', '.so', '.dll', '.exe'}

    # 检查路径中是否包含排除的目录
    for part in file_path.parts:
        if part in excluded_dirs:
            return False

    # 检查文件扩展名
    if file_path.suffix in excluded_patterns:
        return False

    return True


@router.get("/projects/{project_id}/tree", response_model=DirectoryResponse)
async def get_project_tree(
    project_id: str,
    path: str = "",
    db: AsyncSession = Depends(get_db)
):
    """
    获取项目目录结构

    - **path**: 相对路径，空字符串表示根目录
    """
    # 获取项目
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )

    # 构建完整路径
    base_path = Path(project.source_path)
    if not base_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目路径不存在: {project.source_path}"
        )

    target_path = base_path / path if path else base_path

    # 安全检查：确保目标路径在项目目录内
    try:
        target_path = target_path.resolve()
        base_path = base_path.resolve()
        if not str(target_path).startswith(str(base_path)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="访问被拒绝"
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的路径"
        )

    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"路径不存在: {path}"
        )

    if not target_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="指定路径不是目录"
        )

    # 获取目录内容
    items = []
    for item in sorted(target_path.iterdir(), key=lambda x: (not x.is_dir(), x.name)):
        if not _is_allowed_file(item):
            continue

        rel_path = str(item.relative_to(base_path))

        if item.is_dir():
            items.append(FileInfo(
                name=item.name,
                path=rel_path,
                type='directory'
            ))
        else:
            items.append(FileInfo(
                name=item.name,
                path=rel_path,
                type='file',
                extension=item.suffix,
                size=item.stat().st_size
            ))

    return DirectoryResponse(
        project_id=project_id,
        project_name=project.name,
        current_path=path,
        items=items
    )


@router.get("/projects/{project_id}/files", response_model=List[FileInfo])
async def list_all_files(
    project_id: str,
    extension: Optional[str] = Query(None, description="按扩展名过滤，如 .move"),
    db: AsyncSession = Depends(get_db)
):
    """
    获取项目所有文件列表（扁平化）

    - **extension**: 可选，按扩展名过滤
    """
    # 获取项目
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )

    base_path = Path(project.source_path)
    if not base_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目路径不存在: {project.source_path}"
        )

    files = []
    pattern = f"*{extension}" if extension else "*"

    for file_path in base_path.rglob(pattern):
        if not file_path.is_file():
            continue
        if not _is_allowed_file(file_path):
            continue

        rel_path = str(file_path.relative_to(base_path))
        files.append(FileInfo(
            name=file_path.name,
            path=rel_path,
            type='file',
            extension=file_path.suffix,
            size=file_path.stat().st_size
        ))

    # 按路径排序
    files.sort(key=lambda x: x.path)

    return files


@router.get("/projects/{project_id}/content", response_model=FileContentResponse)
async def get_file_content(
    project_id: str,
    path: str = Query(..., description="文件相对路径"),
    db: AsyncSession = Depends(get_db)
):
    """
    获取文件内容

    - **path**: 文件相对路径
    """
    # 获取项目
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )

    base_path = Path(project.source_path)
    file_path = base_path / path

    # 安全检查
    try:
        file_path = file_path.resolve()
        base_path = base_path.resolve()
        if not str(file_path).startswith(str(base_path)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="访问被拒绝"
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的路径"
        )

    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"文件不存在: {path}"
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="指定路径不是文件"
        )

    if not _is_allowed_file(file_path):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="文件类型不允许访问"
        )

    # 读取文件内容
    try:
        content = file_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="文件不是有效的文本文件"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"读取文件失败: {str(e)}"
        )

    return FileContentResponse(
        project_id=project_id,
        file_path=path,
        file_name=file_path.name,
        content=content,
        language=_get_language(path),
        line_count=content.count('\n') + 1
    )


@router.get("/projects/{project_id}/search", response_model=SearchResponse)
async def search_in_project(
    project_id: str,
    q: str = Query(..., min_length=1, description="搜索关键词"),
    extension: Optional[str] = Query(None, description="按扩展名过滤"),
    limit: int = Query(100, le=500, description="最大结果数"),
    db: AsyncSession = Depends(get_db)
):
    """
    在项目中搜索代码

    - **q**: 搜索关键词
    - **extension**: 可选，按扩展名过滤
    - **limit**: 最大结果数
    """
    # 获取项目
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )

    base_path = Path(project.source_path)
    if not base_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目路径不存在: {project.source_path}"
        )

    results = []
    pattern = f"*{extension}" if extension else "*.move"  # 默认只搜索 .move 文件

    for file_path in base_path.rglob(pattern):
        if not file_path.is_file():
            continue
        if not _is_allowed_file(file_path):
            continue

        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            continue

        rel_path = str(file_path.relative_to(base_path))

        for line_num, line in enumerate(content.split('\n'), start=1):
            if q in line:
                match_start = line.find(q)
                results.append(SearchResult(
                    file_path=rel_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    match_start=match_start,
                    match_end=match_start + len(q)
                ))

                if len(results) >= limit:
                    break

        if len(results) >= limit:
            break

    return SearchResponse(
        project_id=project_id,
        query=q,
        total=len(results),
        results=results
    )


@router.post("/projects/{project_id}/locate")
async def locate_function(
    project_id: str,
    module_name: str = Query(..., description="模块名"),
    function_name: Optional[str] = Query(None, description="函数名"),
    db: AsyncSession = Depends(get_db)
) -> CodeLocation:
    """
    定位函数在源代码中的位置

    - **module_name**: 模块名
    - **function_name**: 函数名（可选）
    """
    # 获取项目
    query = select(Project).where(Project.id == project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {project_id}"
        )

    base_path = Path(project.source_path)
    if not base_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目路径不存在: {project.source_path}"
        )

    # 搜索模块定义
    module_pattern = f"module {module_name}" if "::" not in module_name else f"module {module_name.split('::')[-1]}"
    func_pattern = f"fun {function_name}" if function_name else None

    for file_path in base_path.rglob("*.move"):
        if not _is_allowed_file(file_path):
            continue

        try:
            content = file_path.read_text(encoding='utf-8')
            lines = content.split('\n')
        except Exception:
            continue

        rel_path = str(file_path.relative_to(base_path))

        # 查找模块
        module_line = None
        for i, line in enumerate(lines, start=1):
            if module_pattern in line or f"module {module_name.replace('::', '_')}" in line:
                module_line = i
                break

        if module_line is None:
            continue

        # 如果指定了函数名，继续查找函数
        if func_pattern:
            for i, line in enumerate(lines[module_line-1:], start=module_line):
                if func_pattern in line:
                    # 找到函数开始行，计算结束行
                    brace_count = 0
                    func_start = i
                    func_end = i

                    for j, func_line in enumerate(lines[i-1:], start=i):
                        brace_count += func_line.count('{') - func_line.count('}')
                        if brace_count == 0 and '{' in ''.join(lines[i-1:j]):
                            func_end = j
                            break

                    return CodeLocation(
                        file_path=rel_path,
                        line_start=func_start,
                        line_end=func_end,
                        module_name=module_name,
                        function_name=function_name
                    )
        else:
            # 只返回模块位置
            return CodeLocation(
                file_path=rel_path,
                line_start=module_line,
                line_end=module_line,
                module_name=module_name,
                function_name=None
            )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"未找到 {module_name}::{function_name or ''}"
    )
