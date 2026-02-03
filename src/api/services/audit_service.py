"""
审计服务

封装 SecurityAuditEngine 的 Web API 集成逻辑
- 管理运行中的审计任务
- 处理进度回调和日志捕获
- 支持取消任务
"""
import asyncio
import io
import sys
import logging
from datetime import datetime, timezone


def utc_now():
    """返回当前 UTC 时间"""
    return datetime.now(timezone.utc)
from typing import Dict, Optional, Callable, Any, List
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from ...agents.engine import SecurityAuditEngine, AuditConfig, AuditResult, AuditCancelledException
from ...storage.database import Audit, Report, AuditStatus, User, SystemSettings
from .token_service import check_token_quota, record_token_usage, format_token_stats, TokenQuotaExceededError
from ..auth.crypto import decrypt_api_keys


class AuditPhase(str, Enum):
    """审计阶段"""
    INITIALIZING = "initializing"
    ANALYZING = "analyzing"
    SCANNING = "scanning"
    VERIFYING = "verifying"
    EXPLOITING = "exploiting"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AuditProgress:
    """审计进度"""
    phase: int
    phase_name: str
    percent: float
    message: str
    timestamp: datetime = field(default_factory=utc_now)


@dataclass
class AuditRunner:
    """运行中的审计任务"""
    audit_id: str
    engine: SecurityAuditEngine
    task: asyncio.Task
    progress: AuditProgress
    logs: List[str] = field(default_factory=list)
    result: Optional[AuditResult] = None
    error: Optional[str] = None
    user_id: Optional[str] = None  # 🔥 关联用户，用于 token 记录
    project_id: Optional[str] = None  # 🔥 关联项目
    project_name: Optional[str] = None  # 🔥 项目名称

    def add_log(self, message: str):
        """添加日志"""
        timestamp = utc_now().strftime("%H:%M:%S")
        self.logs.append(f"[{timestamp}] {message}")
        # 保留最近1000条日志
        if len(self.logs) > 1000:
            self.logs = self.logs[-1000:]


class AuditService:
    """
    审计服务

    管理所有运行中的审计任务，提供：
    - 启动审计
    - 取消审计
    - 获取进度
    - 获取日志
    """

    _instance: Optional["AuditService"] = None

    def __init__(self):
        self._runners: Dict[str, AuditRunner] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> "AuditService":
        """获取单例实例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def start_audit(
        self,
        audit_id: str,
        project_path: str,
        config: Optional[AuditConfig] = None,
        db: Optional[AsyncSession] = None,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
    ) -> bool:
        """
        启动审计任务

        Args:
            audit_id: 审计任务ID
            project_path: 项目路径
            config: 审计配置
            db: 数据库会话（用于更新状态）
            user_id: 用户ID（用于 token 额度检查和记录）
            project_id: 项目ID
            project_name: 项目名称

        Returns:
            是否启动成功

        Raises:
            TokenQuotaExceededError: Token 额度不足
        """
        async with self._lock:
            if audit_id in self._runners:
                return False  # 任务已存在

            # 🔥 读取用户配置和 API Keys
            user_api_keys = None
            if db and user_id:
                # 检查 Token 额度
                is_allowed, error_msg = await check_token_quota(db, user_id)
                if not is_allowed:
                    raise TokenQuotaExceededError(
                        user_id=user_id,
                        quota=0,
                        used=0,
                    )

                # 读取用户配置
                from sqlalchemy import select
                result = await db.execute(
                    select(User).where(User.id == user_id)
                )
                user = result.scalar_one_or_none()

                if not user:
                    raise ValueError("用户不存在")

                # 检查该用户是否允许使用共享 API Keys
                allow_shared = user.allow_shared_api_keys

                # 如果用户配置了自己的 API Keys，优先使用
                if user.api_keys_encrypted:
                    user_api_keys = decrypt_api_keys(user.api_keys_encrypted)
                # 如果用户没有配置，检查是否允许使用共享
                elif not allow_shared:
                    raise ValueError("管理员要求您使用自己的 API Keys，请先在用户设置中配置")

            # 创建进度回调
            def progress_callback(phase: int, percent: float, message: str):
                if audit_id in self._runners:
                    runner = self._runners[audit_id]
                    phase_names = {
                        0: "initializing",
                        1: "analyzing",
                        2: "scanning",
                        3: "verifying",
                        4: "exploiting",
                        5: "reporting"
                    }
                    runner.progress = AuditProgress(
                        phase=phase,
                        phase_name=phase_names.get(phase, "unknown"),
                        percent=percent,
                        message=message
                    )
                    runner.add_log(f"[Phase {phase}] {message}")

            # 创建引擎（传入用户 API Keys）
            engine = SecurityAuditEngine(
                config=config or AuditConfig(),
                project_path=project_path,
                progress_callback=progress_callback,
                api_keys=user_api_keys  # 🔥 用户自定义 API Keys
            )

            # 初始进度
            initial_progress = AuditProgress(
                phase=0,
                phase_name="initializing",
                percent=0,
                message="审计任务已创建，等待启动..."
            )

            # 创建任务
            task = asyncio.create_task(
                self._run_audit(audit_id, engine, project_path, db, user_id, project_id, project_name)
            )

            # 注册运行器
            runner = AuditRunner(
                audit_id=audit_id,
                engine=engine,
                task=task,
                progress=initial_progress,
                user_id=user_id,
                project_id=project_id,
                project_name=project_name,
            )
            self._runners[audit_id] = runner

            return True

    async def _run_audit(
        self,
        audit_id: str,
        engine: SecurityAuditEngine,
        project_path: str,
        db: Optional[AsyncSession],
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
    ):
        """执行审计任务"""
        runner = self._runners.get(audit_id)
        if not runner:
            return

        audit_status = "completed"
        try:
            runner.add_log("开始审计...")

            # 读取项目代码
            code = self._read_project_code(project_path)
            if not code:
                raise ValueError(f"无法读取项目代码: {project_path}")

            runner.add_log(f"已加载项目代码，共 {len(code)} 字符")

            # 执行审计
            result = await engine.audit(code)
            runner.result = result
            runner.add_log(f"审计完成，发现 {result.statistics.get('total_findings', 0)} 个漏洞")

            # 更新数据库状态
            if db:
                await self._update_audit_completed(audit_id, result, db)

        except AuditCancelledException:
            runner.error = "审计已被取消"
            runner.add_log("审计已被用户取消")
            audit_status = "cancelled"
            if db:
                await self._update_audit_cancelled(audit_id, db)

        except Exception as e:
            runner.error = str(e)
            runner.add_log(f"审计失败: {e}")
            audit_status = "failed"
            if db:
                await self._update_audit_failed(audit_id, str(e), db)

        finally:
            # 🔥 记录 Token 使用量
            if db and user_id:
                await self._record_token_usage(
                    db=db,
                    engine=engine,
                    user_id=user_id,
                    project_id=project_id,
                    project_name=project_name,
                    audit_id=audit_id,
                    audit_status=audit_status,
                )

    async def _record_token_usage(
        self,
        db: AsyncSession,
        engine: SecurityAuditEngine,
        user_id: str,
        project_id: Optional[str],
        project_name: Optional[str],
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

        except Exception as e:
            logging.error(f"记录 Token 使用量失败: {e}")

    def _read_project_code(self, project_path: str) -> str:
        """读取项目所有 Move 代码"""
        path = Path(project_path)
        if not path.exists():
            return ""

        code_parts = []

        # 查找所有 .move 文件
        for move_file in path.rglob("*.move"):
            try:
                content = move_file.read_text(encoding="utf-8")
                # 添加文件标记
                relative_path = move_file.relative_to(path)
                code_parts.append(f"// === File: {relative_path} ===\n{content}")
            except Exception as e:
                print(f"Warning: Cannot read {move_file}: {e}")

        return "\n\n".join(code_parts)

    async def cancel_audit(self, audit_id: str) -> bool:
        """
        取消审计任务

        Returns:
            是否取消成功
        """
        async with self._lock:
            runner = self._runners.get(audit_id)
            if not runner:
                return False

            # 调用引擎的取消方法
            runner.engine.cancel()
            runner.add_log("正在取消审计...")

            # 等待任务结束（最多5秒）
            try:
                await asyncio.wait_for(runner.task, timeout=5.0)
            except asyncio.TimeoutError:
                # 强制取消
                runner.task.cancel()
                runner.add_log("任务已强制取消")

            return True

    def get_progress(self, audit_id: str) -> Optional[AuditProgress]:
        """获取审计进度"""
        runner = self._runners.get(audit_id)
        if runner:
            return runner.progress
        return None

    def get_logs(self, audit_id: str, offset: int = 0) -> List[str]:
        """获取审计日志"""
        runner = self._runners.get(audit_id)
        if runner:
            return runner.logs[offset:]
        return []

    def get_result(self, audit_id: str) -> Optional[AuditResult]:
        """获取审计结果"""
        runner = self._runners.get(audit_id)
        if runner:
            return runner.result
        return None

    def get_error(self, audit_id: str) -> Optional[str]:
        """获取错误信息"""
        runner = self._runners.get(audit_id)
        if runner:
            return runner.error
        return None

    def is_running(self, audit_id: str) -> bool:
        """检查审计是否在运行"""
        runner = self._runners.get(audit_id)
        if runner:
            return not runner.task.done()
        return False

    def cleanup(self, audit_id: str):
        """清理已完成的任务"""
        if audit_id in self._runners:
            runner = self._runners[audit_id]
            if runner.task.done():
                del self._runners[audit_id]

    async def _update_audit_completed(
        self,
        audit_id: str,
        result: AuditResult,
        db: AsyncSession
    ):
        """更新数据库：审计完成"""
        from sqlalchemy import select

        query = select(Audit).where(Audit.id == audit_id)
        audit_result = await db.execute(query)
        audit = audit_result.scalar_one_or_none()

        if audit:
            audit.status = AuditStatus.COMPLETED
            audit.completed_at = utc_now()
            audit.progress = {
                "phase": 5,
                "percent": 100,
                "message": "审计完成"
            }

            # 创建报告
            report = Report(
                audit_id=audit_id,
                findings=result.verified_findings,
                summary=result.statistics,
                risk_score=self._calculate_risk_score(result),
                total_findings=result.statistics.get("total_findings", 0),
                critical_count=result.statistics.get("by_severity", {}).get("CRITICAL", 0),
                high_count=result.statistics.get("by_severity", {}).get("HIGH", 0),
                medium_count=result.statistics.get("by_severity", {}).get("MEDIUM", 0),
                low_count=result.statistics.get("by_severity", {}).get("LOW", 0),
                advisory_count=result.statistics.get("by_severity", {}).get("ADVISORY", 0),
            )
            db.add(report)

            await db.commit()

    async def _update_audit_cancelled(self, audit_id: str, db: AsyncSession):
        """更新数据库：审计取消"""
        from sqlalchemy import select

        query = select(Audit).where(Audit.id == audit_id)
        result = await db.execute(query)
        audit = result.scalar_one_or_none()

        if audit:
            audit.status = AuditStatus.CANCELLED
            audit.completed_at = utc_now()
            await db.commit()

    async def _update_audit_failed(self, audit_id: str, error: str, db: AsyncSession):
        """更新数据库：审计失败"""
        from sqlalchemy import select

        query = select(Audit).where(Audit.id == audit_id)
        result = await db.execute(query)
        audit = result.scalar_one_or_none()

        if audit:
            audit.status = AuditStatus.FAILED
            audit.error_message = error
            audit.completed_at = utc_now()
            await db.commit()

    def _calculate_risk_score(self, result: AuditResult) -> float:
        """计算风险评分"""
        stats = result.statistics.get("by_severity", {})
        score = (
            stats.get("CRITICAL", 0) * 40 +
            stats.get("HIGH", 0) * 25 +
            stats.get("MEDIUM", 0) * 15 +
            stats.get("LOW", 0) * 8 +
            stats.get("ADVISORY", 0) * 4
        )
        return min(100.0, score)


def get_audit_service() -> AuditService:
    """获取审计服务实例"""
    return AuditService.get_instance()
