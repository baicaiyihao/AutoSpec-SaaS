"""
审计任务 API 路由

v2.6.0: 集成 SecurityAuditEngine，支持真实审计执行
"""
import asyncio
import threading
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc)
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..models.audit import (
    AuditCreate,
    AuditResponse,
    AuditListResponse,
    AuditProgress,
    AuditStatusEnum,
)
from ..services.audit_service import get_audit_service, AuditService
from ..auth.dependencies import get_current_user
from ...storage.database import (
    get_db,
    Project,
    Audit,
    Report,
    FindingMark,
    AuditStatus,
    User,
    UserRole,
)
from ...agents.engine import AuditConfig
from ..services.token_service import check_token_quota, check_audit_permission, record_token_usage, format_token_stats


router = APIRouter(prefix="/audits", tags=["audits"])


def _check_audit_owner(audit: Audit, user: User):
    """检查审计任务所有权"""
    if user.role == UserRole.ADMIN:
        return
    if audit.owner_id and audit.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="无权访问该审计任务")


def _audit_to_response(audit: Audit, project_name: str = "Unknown", report_id: str = None) -> AuditResponse:
    """
    将 ORM 对象转换为响应模型

    注意：为避免异步环境中的延迟加载问题，project_name 和 report_id 需要预先获取并传入
    """
    progress = None
    if audit.progress:
        progress = AuditProgress(**audit.progress)

    return AuditResponse(
        id=audit.id,
        project_id=audit.project_id,
        project_name=project_name,
        status=AuditStatusEnum(audit.status.value),
        config=audit.config or {},
        progress=progress,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
        error_message=audit.error_message,
        report_id=report_id,
        created_at=audit.created_at,
    )


class AuditLogsResponse(BaseModel):
    """审计日志响应"""
    audit_id: str
    logs: List[str]
    total: int
    is_running: bool


async def run_audit_task(
    audit_id: str,
    project_path: str,
    project_name: str,
    config: dict,
    user_id: str = None,
    project_id: str = None,
):
    """
    后台执行审计任务

    v2.6.0: 直接执行 SecurityAuditEngine，简化流程
    v2.6.1: 捕获详细日志输出
    v2.6.2: 传递项目名称用于报告生成
    v2.6.3: Token 使用量记录
    """
    import sys
    import io
    from pathlib import Path
    from ...storage.database import _get_session_factory
    from ...agents.engine import SecurityAuditEngine, AuditConfig as EngineAuditConfig

    # 用于存储日志的列表
    logs: List[str] = []
    last_log_update = [0]  # 使用列表来在闭包中修改

    def get_timestamp():
        from datetime import timezone, timedelta
        utc8 = timezone(timedelta(hours=8))
        return datetime.now(utc8).strftime("%H:%M:%S")

    def add_log(msg: str):
        timestamp = get_timestamp()
        logs.append(f"[{timestamp}] {msg}")
        print(f"[Audit {audit_id[:8]}] {msg}")  # 也打印到控制台

    # 保存原始 stdout 用于 add_log（避免被 LogCapture 重复捕获）
    original_stdout_for_log = sys.stdout

    # 自定义 stdout 捕获类 - 捕获引擎的详细输出
    class LogCapture:
        def __init__(self, original_stdout, audit_id, logs_ref):
            self.original = original_stdout
            self.audit_id = audit_id
            self.logs_ref = logs_ref
            self.buffer = ""  # 用于处理不完整的行

        def write(self, text):
            self.original.write(text)  # 同时输出到原始 stdout

            if not text:
                return

            # 过滤掉 add_log 产生的输出，避免重复
            if f'[Audit {self.audit_id[:8]}]' in text:
                return

            # 将文本添加到缓冲区
            self.buffer += text

            # 处理完整的行
            while '\n' in self.buffer:
                line, self.buffer = self.buffer.split('\n', 1)
                line = line.strip()

                if not line or len(line) <= 1:
                    continue

                # 过滤掉一些不需要的输出
                skip_patterns = [
                    'INFO sqlalchemy', 'BEGIN (implicit)', 'COMMIT', 'ROLLBACK',
                    'SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ',
                    '[cached since', 'generated in', '... (10 characters truncated)',
                    'sqlalchemy.engine.Engine'
                ]

                if any(p in line for p in skip_patterns):
                    continue

                # 清理一些常见的日志前缀
                clean_line = line
                # 移除 logging 模块的时间戳前缀（如果已经有时间了）
                if clean_line.startswith('20') and ' - ' in clean_line[:30]:
                    # 格式如: 2025-01-22 10:30:45,123 - module - INFO - message
                    parts = clean_line.split(' - ', 3)
                    if len(parts) >= 4:
                        clean_line = parts[-1]  # 只保留消息部分
                    elif len(parts) >= 2:
                        clean_line = parts[-1]

                # 添加带时间戳的日志
                self.logs_ref.append(f"[{get_timestamp()}] {clean_line}")

        def flush(self):
            self.original.flush()

            # 处理缓冲区中剩余的内容
            if self.buffer.strip():
                line = self.buffer.strip()
                if len(line) > 1:
                    self.logs_ref.append(f"[{get_timestamp()}] {line}")
                self.buffer = ""

    session_factory = _get_session_factory()

    try:
        async with session_factory() as db:
            # 获取审计任务
            query = select(Audit).where(Audit.id == audit_id)
            result = await db.execute(query)
            audit = result.scalar_one_or_none()

            if not audit:
                add_log("审计任务不存在")
                return

            # 更新状态为运行中
            audit.status = AuditStatus.RUNNING
            audit.started_at = utc_now()
            audit.progress = {
                "current_phase": 0,
                "phase_name": "初始化",
                "progress_percent": 0.0,
                "messages": []  # 初始为空，后续由 add_log 添加带时间戳的日志
            }
            await db.commit()
            add_log("审计任务启动")

        # 读取项目代码
        add_log(f"读取项目代码: {project_path}")
        code = _read_project_code(project_path)
        if not code:
            raise ValueError(f"无法读取项目代码或没有 .move 文件: {project_path}")
        add_log(f"已加载 {len(code)} 字符的代码")

        # 创建进度回调
        def progress_callback(phase: int, percent: float, message: str):
            add_log(f">>> Phase {phase}: {message} ({percent:.0f}%)")
            # 同步更新数据库进度（在独立线程的事件循环中运行）
            try:
                loop = asyncio.get_event_loop()
                # 传递所有日志（限制最多500条），确保offset逻辑正确
                asyncio.ensure_future(_update_progress(audit_id, phase, percent, message, logs[-500:]))
            except Exception as e:
                pass  # 静默处理，避免污染日志

        # 构建审计配置
        engine_config = EngineAuditConfig()
        if config:
            if config.get("use_simplified_architecture") is not None:
                engine_config.use_simplified_architecture = config["use_simplified_architecture"]
            if config.get("enable_exploit_verification") is not None:
                engine_config.enable_exploit_verification = config["enable_exploit_verification"]

        # 创建引擎并执行审计
        add_log("创建审计引擎")
        engine = SecurityAuditEngine(
            config=engine_config,
            project_path=project_path,
            progress_callback=progress_callback
        )

        add_log("开始执行审计...")

        # 捕获 stdout 和 stderr 以获取详细日志
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        stdout_capture = LogCapture(original_stdout, audit_id, logs)
        stderr_capture = LogCapture(original_stderr, audit_id, logs)
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        # 定期更新日志到数据库的任务
        log_update_running = [True]  # 使用列表以便在闭包中修改
        last_log_count = [0]

        async def periodic_log_update():
            """每2秒更新一次日志到数据库"""
            while log_update_running[0]:
                await asyncio.sleep(2)
                current_count = len(logs)
                if current_count > last_log_count[0]:
                    last_log_count[0] = current_count
                    # 只更新日志，不改变进度
                    await _update_progress(audit_id, -1, -1, "", logs[-500:])

        # 启动定期更新任务
        log_update_task = asyncio.create_task(periodic_log_update())

        try:
            audit_result = await engine.audit(code, project_name=project_name)
        finally:
            # 停止定期更新
            log_update_running[0] = False
            try:
                log_update_task.cancel()
                await log_update_task
            except asyncio.CancelledError:
                pass

            # 确保恢复原始输出
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            # 刷新捕获器以处理剩余内容
            stdout_capture.flush()
            stderr_capture.flush()

        add_log(f">>> 审计完成，发现 {audit_result.statistics.get('confirmed', 0)} 个漏洞")

        # 更新数据库状态为完成
        async with session_factory() as db:
            query = select(Audit).where(Audit.id == audit_id)
            result = await db.execute(query)
            audit = result.scalar_one_or_none()

            if audit:
                audit.status = AuditStatus.COMPLETED
                audit.completed_at = utc_now()
                audit.progress = {
                    "current_phase": 5,
                    "phase_name": "完成",
                    "progress_percent": 100.0,
                    "messages": logs[-500:]  # 保留更多日志用于查看
                }

                # 创建报告 - 将 VerifiedFinding 对象序列化为字典
                serialized_findings = _serialize_findings(audit_result.verified_findings)

                # 获取报告文件路径（从 SecurityAuditEngine 生成的 report_dir）
                report_file_path = None
                if audit_result.report_dir:
                    report_file_path = f"{audit_result.report_dir}/security_report.md"

                # 从 statistics 中提取数据（注意字段名匹配）
                stats = audit_result.statistics
                severity_dist = stats.get("severity_distribution", {})

                report = Report(
                    audit_id=audit_id,
                    findings=serialized_findings,
                    summary=stats,
                    risk_score=_calculate_risk_score(stats),
                    total_findings=stats.get("confirmed", 0),  # 使用 confirmed 而非 total_findings
                    critical_count=severity_dist.get("critical", 0),  # 小写
                    high_count=severity_dist.get("high", 0),
                    medium_count=severity_dist.get("medium", 0),
                    low_count=severity_dist.get("low", 0),
                    advisory_count=severity_dist.get("advisory", 0),
                    report_path=report_file_path,
                )
                db.add(report)
                await db.commit()
                add_log(f"报告已保存: {report.id}")

                # 🔥 记录 Token 使用量
                if user_id:
                    await _record_audit_token_usage(
                        session_factory, engine, user_id, project_id,
                        project_name, audit_id, "completed"
                    )
                    add_log("Token 使用量已记录")

    except Exception as e:
        add_log(f"审计失败: {e}")
        import traceback
        traceback.print_exc()

        # 🔥 即使失败也记录 Token 使用量
        if user_id:
            try:
                await _record_audit_token_usage(
                    session_factory, engine, user_id, project_id,
                    project_name, audit_id, "failed"
                )
            except Exception:
                pass

        # 更新数据库状态为失败
        async with session_factory() as db:
            query = select(Audit).where(Audit.id == audit_id)
            result = await db.execute(query)
            audit = result.scalar_one_or_none()

            if audit:
                audit.status = AuditStatus.FAILED
                audit.error_message = str(e)
                audit.completed_at = utc_now()
                audit.progress = {
                    "current_phase": 0,
                    "phase_name": "失败",
                    "progress_percent": 0.0,
                    "messages": logs[-500:]  # 保留更多日志用于排查
                }
                await db.commit()


async def _record_audit_token_usage(
    session_factory,
    engine,
    user_id: str,
    project_id: str,
    project_name: str,
    audit_id: str,
    audit_status: str,
):
    """🔥 记录审计的 Token 使用量"""
    try:
        # 从引擎获取 token 统计
        agent_stats = {}
        total_prompt = 0
        total_completion = 0
        total_tokens = 0

        for agent_name, agent in engine._get_all_agents():
            if hasattr(agent, 'get_token_usage'):
                usage = agent.get_token_usage()
                if usage.get('call_count', 0) > 0:
                    agent_stats[agent_name] = usage
                    total_prompt += usage.get('prompt_tokens', 0)
                    total_completion += usage.get('completion_tokens', 0)
                    total_tokens += usage.get('total_tokens', 0)

        if total_tokens > 0:
            async with session_factory() as db:
                await record_token_usage(
                    db=db,
                    user_id=user_id,
                    total_tokens=total_tokens,
                    prompt_tokens=total_prompt,
                    completion_tokens=total_completion,
                    agent_breakdown=format_token_stats(agent_stats),
                    project_id=project_id,
                    project_name=project_name,
                    audit_id=audit_id,
                    audit_status=audit_status,
                )
                await db.commit()
                print(f"[Audit {audit_id[:8]}] Token 使用量已记录: {total_tokens:,} tokens")

    except Exception as e:
        print(f"[Audit {audit_id[:8]}] 记录 Token 使用量失败: {e}")


async def _update_progress(audit_id: str, phase: int, percent: float, message: str, logs: List[str]):
    """异步更新审计进度

    当 phase == -1 时，只更新日志，保留原有的 phase/percent 值
    """
    from ...storage.database import _get_session_factory

    try:
        session_factory = _get_session_factory()
        async with session_factory() as db:
            query = select(Audit).where(Audit.id == audit_id)
            result = await db.execute(query)
            audit = result.scalar_one_or_none()

            if audit and audit.status == AuditStatus.RUNNING:
                phase_names = {0: "初始化", 1: "代码分析", 2: "漏洞扫描", 3: "Agent验证", 4: "利用链验证", 5: "生成报告"}

                # 如果 phase == -1，只更新日志，保留原有进度
                if phase == -1:
                    existing = audit.progress or {}
                    audit.progress = {
                        "current_phase": existing.get("current_phase", 0),
                        "phase_name": existing.get("phase_name", "运行中"),
                        "progress_percent": existing.get("progress_percent", 0),
                        "messages": logs
                    }
                else:
                    audit.progress = {
                        "current_phase": phase,
                        "phase_name": phase_names.get(phase, message),
                        "progress_percent": percent,
                        "messages": logs
                    }
                await db.commit()
    except Exception as e:
        print(f"Update progress error: {e}")


def _read_project_code(project_path: str) -> str:
    """读取项目所有 Move 代码"""
    from pathlib import Path

    path = Path(project_path)
    if not path.exists():
        return ""

    code_parts = []
    for move_file in path.rglob("*.move"):
        rel_str = str(move_file.relative_to(path))
        # 排除 build 目录和依赖
        if rel_str.startswith("build/") or "/dependencies/" in rel_str:
            continue
        try:
            content = move_file.read_text(encoding="utf-8")
            code_parts.append(f"// === File: {rel_str} ===\n{content}")
        except Exception as e:
            print(f"Warning: Cannot read {move_file}: {e}")

    return "\n\n".join(code_parts)


def _calculate_risk_score(statistics: dict) -> float:
    """计算风险评分

    statistics 结构来自 SecurityAuditEngine._calculate_statistics():
    {
        "confirmed": 6,
        "severity_distribution": {"critical": 1, "high": 3, "medium": 2, "low": 0, "advisory": 0}
    }
    """
    severity_dist = statistics.get("severity_distribution", {})
    score = (
        severity_dist.get("critical", 0) * 40 +
        severity_dist.get("high", 0) * 25 +
        severity_dist.get("medium", 0) * 15 +
        severity_dist.get("low", 0) * 8 +
        severity_dist.get("advisory", 0) * 4
    )
    return min(100.0, float(score))


def _serialize_findings(findings: list) -> list:
    """
    将 VerifiedFinding 对象列表转换为可 JSON 序列化的字典列表

    处理 dataclass、Enum 等不可直接序列化的类型
    """
    from dataclasses import asdict, is_dataclass
    from enum import Enum

    def serialize_value(obj):
        """递归序列化单个值"""
        if obj is None:
            return None
        elif isinstance(obj, Enum):
            return obj.value
        elif is_dataclass(obj) and not isinstance(obj, type):
            # 是 dataclass 实例
            return {k: serialize_value(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, dict):
            return {k: serialize_value(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [serialize_value(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        else:
            # 其他类型尝试转为字符串
            return str(obj)

    return [serialize_value(f) for f in findings]


@router.post("", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
async def create_audit(
    request: AuditCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    创建审计任务

    任务将在后台执行，可通过轮询获取进度
    """
    # 🔥 检查审计权限（付费模式 + API Key / Token 余额）
    is_allowed, error_msg = await check_audit_permission(db, user.id)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
        )

    # 🔥 检查 Token 额度（管理员配置的配额限制）
    quota_ok, quota_msg = await check_token_quota(db, user.id)
    if not quota_ok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token 额度不足: {quota_msg}"
        )

    # 验证项目存在
    query = select(Project).where(Project.id == request.project_id)
    result = await db.execute(query)
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"项目不存在: {request.project_id}"
        )

    # 检查是否已有运行中的审计任务
    running_query = select(Audit).where(
        Audit.project_id == request.project_id,
        Audit.status.in_([AuditStatus.PENDING, AuditStatus.RUNNING])
    )
    running_result = await db.execute(running_query)
    running_audit = running_result.scalar_one_or_none()

    if running_audit:
        # 返回已有的运行中任务
        return _audit_to_response(running_audit, project_name=project.name, report_id=None)

    # 创建审计任务
    audit = Audit(
        project_id=request.project_id,
        owner_id=user.id,
        status=AuditStatus.PENDING,
        config=request.config.model_dump() if request.config else {},
    )

    db.add(audit)
    await db.flush()
    await db.refresh(audit)

    # 保存项目信息用于响应
    project_name = project.name
    source_path = project.source_path
    config = audit.config
    audit_id = audit.id
    user_id = user.id
    project_id = project.id

    # 在后台线程中运行审计任务，避免阻塞主事件循环
    # SecurityAuditEngine 内部有同步阻塞操作（LLM API调用），需要在线程中运行
    def run_in_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_audit_task(
                audit_id, source_path, project_name, config,
                user_id=user_id, project_id=project_id  # 🔥 传递用户和项目信息用于 token 记录
            ))
        finally:
            loop.close()

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()
    print(f"[Audit] Task started in background thread for {audit_id[:8]}, project: {project_name}")

    return _audit_to_response(audit, project_name=project_name, report_id=None)


@router.get("", response_model=AuditListResponse)
async def list_audits(
    project_id: Optional[str] = None,
    status: Optional[AuditStatusEnum] = None,
    skip: int = 0,
    limit: int = 20,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取审计任务列表"""
    limit = min(limit, 100)

    # 构建查询
    query = select(Audit).options(
        selectinload(Audit.project),
        selectinload(Audit.report)
    )

    if project_id:
        query = query.where(Audit.project_id == project_id)
    if status:
        query = query.where(Audit.status == AuditStatus(status.value))
    if user.role != UserRole.ADMIN:
        query = query.where(Audit.owner_id == user.id)

    # 查询总数
    count_query = select(func.count(Audit.id))
    if project_id:
        count_query = count_query.where(Audit.project_id == project_id)
    if status:
        count_query = count_query.where(Audit.status == AuditStatus(status.value))
    if user.role != UserRole.ADMIN:
        count_query = count_query.where(Audit.owner_id == user.id)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # 查询列表
    query = query.order_by(Audit.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    audits = result.scalars().all()

    return AuditListResponse(
        total=total,
        items=[
            _audit_to_response(
                a,
                project_name=a.project.name if a.project else "Unknown",
                report_id=a.report.id if a.report else None
            )
            for a in audits
        ]
    )


@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(
    audit_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取审计任务详情"""
    query = (
        select(Audit)
        .options(selectinload(Audit.project), selectinload(Audit.report))
        .where(Audit.id == audit_id)
    )
    result = await db.execute(query)
    audit = result.scalar_one_or_none()

    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )
    _check_audit_owner(audit, user)

    return _audit_to_response(
        audit,
        project_name=audit.project.name if audit.project else "Unknown",
        report_id=audit.report.id if audit.report else None
    )


@router.post("/{audit_id}/cancel", response_model=AuditResponse)
async def cancel_audit(
    audit_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    取消审计任务

    v2.6.0: 使用 AuditService 取消运行中的审计
    """
    query = (
        select(Audit)
        .options(selectinload(Audit.project), selectinload(Audit.report))
        .where(Audit.id == audit_id)
    )
    result = await db.execute(query)
    audit = result.scalar_one_or_none()

    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )
    _check_audit_owner(audit, user)

    if audit.status not in [AuditStatus.PENDING, AuditStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"无法取消状态为 {audit.status.value} 的任务"
        )

    # 使用 AuditService 取消任务
    service = get_audit_service()
    if service.is_running(audit_id):
        await service.cancel_audit(audit_id)

    # 保存项目名称（refresh 后关系会丢失）
    project_name = audit.project.name if audit.project else "Unknown"
    report_id = audit.report.id if audit.report else None

    # 更新数据库状态
    audit.status = AuditStatus.CANCELLED
    audit.completed_at = utc_now()

    await db.flush()
    await db.refresh(audit)

    return _audit_to_response(audit, project_name=project_name, report_id=report_id)


@router.get("/{audit_id}/logs", response_model=AuditLogsResponse)
async def get_audit_logs(
    audit_id: str,
    offset: int = 0,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    获取审计任务日志

    - **offset**: 从第几条日志开始获取（用于增量获取）

    返回：
    - logs: 日志列表（从 offset 开始的新日志）
    - total: 当前总日志数
    - is_running: 任务是否仍在运行
    """
    # 验证审计任务存在
    query = select(Audit).where(Audit.id == audit_id)
    result = await db.execute(query)
    audit = result.scalar_one_or_none()

    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )
    _check_audit_owner(audit, user)

    # 直接从数据库获取日志（审计任务在独立线程中运行，会定期更新数据库）
    db_progress = audit.progress or {}
    all_logs = db_progress.get("messages", [])
    logs = all_logs[offset:] if offset < len(all_logs) else []
    is_running = audit.status in [AuditStatus.PENDING, AuditStatus.RUNNING]

    return AuditLogsResponse(
        audit_id=audit_id,
        logs=logs,
        total=len(all_logs),
        is_running=is_running
    )


@router.get("/{audit_id}/progress")
async def get_audit_progress(
    audit_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    获取审计任务实时进度

    返回：
    - phase: 当前阶段 (0-5)
    - phase_name: 阶段名称
    - percent: 完成百分比 (0-100)
    - message: 当前状态消息
    - is_running: 是否仍在运行
    """
    # 验证审计任务存在
    query = select(Audit).where(Audit.id == audit_id)
    result = await db.execute(query)
    audit = result.scalar_one_or_none()

    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )
    _check_audit_owner(audit, user)

    # 直接从数据库获取进度（审计任务在独立线程中运行，会定期更新数据库）
    db_progress = audit.progress or {}
    is_running = audit.status in [AuditStatus.PENDING, AuditStatus.RUNNING]

    # 获取最后一条消息作为当前消息
    messages = db_progress.get("messages", [])
    last_message = messages[-1] if messages else db_progress.get("phase_name", "")

    return {
        "audit_id": audit_id,
        "phase": db_progress.get("current_phase", 0),
        "phase_name": db_progress.get("phase_name", "initializing"),
        "percent": db_progress.get("progress_percent", 0),
        "message": last_message,
        "is_running": is_running
    }


@router.delete("/{audit_id}")
async def delete_audit(
    audit_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """删除审计任务及其关联的报告（通过 ORM cascade 自动级联删除）"""
    query = (
        select(Audit)
        .options(selectinload(Audit.report))
        .where(Audit.id == audit_id)
    )
    result = await db.execute(query)
    audit = result.scalar_one_or_none()

    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )
    _check_audit_owner(audit, user)

    # 如果有关联报告，先手动删除其子关系（ReviewSession、FindingMark）
    # 因为 async session 中 cascade 可能不会自动加载子对象
    if audit.report:
        report = audit.report
        # 删除 review sessions
        from ...storage.database import ReviewSession
        sessions_q = select(ReviewSession).where(ReviewSession.report_id == report.id)
        sessions_r = await db.execute(sessions_q)
        for s in sessions_r.scalars().all():
            await db.delete(s)
        # 删除 finding marks
        marks_q = select(FindingMark).where(FindingMark.report_id == report.id)
        marks_r = await db.execute(marks_q)
        for m in marks_r.scalars().all():
            await db.delete(m)
        # 删除报告
        await db.delete(report)

    await db.delete(audit)
    await db.flush()

    return {"detail": "审计任务已删除"}
