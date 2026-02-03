"""
Review 模式 API 路由

实现漏洞聚焦对话和人工确认/驳回功能
"""
import asyncio
import json
import logging
import queue
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc)
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

logger = logging.getLogger(__name__)

from ..models.review import (
    ReviewSessionCreate,
    ReviewSessionResponse,
    ReviewActionRequest,
    ReviewMessage as ReviewMessageSchema,
    ReviewAction as ReviewActionSchema,
    ChatRequest,
    ChatResponse,
    FocusRequest,
)
from ..auth.dependencies import get_current_user
from ...storage.database import (
    get_db,
    _get_session_factory,
    Report,
    ReviewSession,
    ReviewMessage,
    ReviewAction,
    ReviewActionType,
    FindingMark,
    FindingMarkType,
    User,
)


router = APIRouter(prefix="/review", tags=["review"])


# =============================================================================
# ReviewAgent 集成
# =============================================================================

from ...storage.database import Audit, Project

# 缓存: project_id → ReviewAgent (避免重复初始化)
_project_agents: Dict[str, "ReviewAgent"] = {}


def _get_review_agent(project_path: str, project_id: str):
    """
    获取或创建 ReviewAgent (per-project 缓存)

    使用与其他 Agent 相同的 AgentConfig 模式，
    自动检测可用的 LLM Provider。
    """
    from ...agents.review_agent import ReviewAgent

    if project_id in _project_agents:
        return _project_agents[project_id]

    try:
        # 1. 获取 LLM 配置 (与审计引擎相同的 auto-detect 逻辑)
        from ...config import get_agent_configs
        from ...agents.base_agent import AgentConfig

        configs = get_agent_configs("auto")
        agent_config = configs.get("review")

        if not agent_config:
            # Fallback: 使用 DashScope
            agent_config = AgentConfig(
                provider="dashscope",
                model="qwen-plus",
                temperature=0.3,
                max_tokens=4096,
            )

        # 2. 创建项目索引和工具箱
        toolkit = None
        try:
            from ...context.project_indexer import MoveProjectIndexer
            from ...agents.tools import AgentToolkit
            from ...security.pattern_scan import SecurityScanner

            indexer = MoveProjectIndexer(project_path)
            indexer.index_project(build_callgraph=True)

            # SecurityScanner 用于 RAG 漏洞模式搜索
            try:
                scanner = SecurityScanner(use_vector_db=True)
            except Exception:
                scanner = None

            toolkit = AgentToolkit(indexer, security_scanner=scanner)
            logger.info(f"ReviewAgent toolkit 初始化成功: {project_path}")
        except Exception as e:
            logger.warning(f"ReviewAgent toolkit 初始化失败 (将无工具模式运行): {e}")

        # 3. 创建 ReviewAgent
        agent = ReviewAgent(config=agent_config)
        if toolkit:
            agent.set_toolkit(toolkit)

        _project_agents[project_id] = agent
        logger.info(f"ReviewAgent 创建成功: project_id={project_id}, provider={agent_config.provider}")
        return agent

    except Exception as e:
        logger.error(f"ReviewAgent 创建失败: {e}")
        raise


async def _get_project_path(report, db: AsyncSession) -> tuple:
    """
    从 Report 获取 Project 路径

    Returns:
        (project_path, project_id) 或 raise HTTPException
    """
    # 加载 Audit → Project 关系
    audit_query = (
        select(Audit)
        .options(selectinload(Audit.project))
        .where(Audit.id == report.audit_id)
    )
    result = await db.execute(audit_query)
    audit = result.scalar_one_or_none()

    if not audit or not audit.project:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="无法获取项目信息"
        )

    return audit.project.source_path, audit.project.id


def _session_to_response(session: ReviewSession) -> ReviewSessionResponse:
    """将 ORM 对象转换为响应模型"""
    messages = [
        ReviewMessageSchema(
            id=m.id,
            role=m.role,
            content=m.content,
            metadata=m.extra_data,
            created_at=m.created_at,
        )
        for m in (session.messages or [])
    ]

    actions = [
        ReviewActionSchema(
            id=a.id,
            finding_id=a.finding_id,
            action_type=a.action_type,
            from_value=a.from_value,
            to_value=a.to_value,
            reason=a.reason,
            ai_analysis=a.ai_analysis,
            created_at=a.created_at,
        )
        for a in (session.actions or [])
    ]

    return ReviewSessionResponse(
        id=session.id,
        report_id=session.report_id,
        focused_finding_id=session.focused_finding_id,
        is_active=session.is_active,
        messages=messages,
        actions=actions,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


@router.post("/sessions", response_model=ReviewSessionResponse, status_code=status.HTTP_201_CREATED)
async def create_session(
    request: ReviewSessionCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    创建 Review 会话

    - **report_id**: 报告 ID
    - **initial_finding_id**: 初始聚焦的漏洞 ID（可选）
    """
    # 验证报告存在
    query = select(Report).where(Report.id == request.report_id)
    result = await db.execute(query)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"报告不存在: {request.report_id}"
        )

    # 如果指定了漏洞 ID，验证其存在
    if request.initial_finding_id:
        finding_exists = any(
            f.get("id") == request.initial_finding_id
            for f in (report.findings or [])
        )
        if not finding_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"漏洞不存在: {request.initial_finding_id}"
            )

    # 创建会话
    session = ReviewSession(
        report_id=request.report_id,
        focused_finding_id=request.initial_finding_id,
        is_active=True,
    )

    # 添加系统消息
    if request.initial_finding_id:
        # 获取漏洞信息
        finding = next(
            (f for f in (report.findings or []) if f.get("id") == request.initial_finding_id),
            None
        )
        if finding:
            system_msg = ReviewMessage(
                session_id=session.id,
                role="system",
                content=f"已聚焦到漏洞: {finding.get('title')}\n严重性: {finding.get('severity')}\n描述: {finding.get('description', '')[:200]}...",
            )
            session.messages = [system_msg]

    db.add(session)
    await db.flush()

    # Re-query with eager loading to avoid lazy-load errors in async context
    query = (
        select(ReviewSession)
        .options(
            selectinload(ReviewSession.messages),
            selectinload(ReviewSession.actions),
        )
        .where(ReviewSession.id == session.id)
    )
    result = await db.execute(query)
    session = result.scalar_one()

    return _session_to_response(session)


@router.get("/sessions/list/{report_id}")
async def list_sessions(
    report_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取报告的所有 Review 会话列表"""
    query = (
        select(ReviewSession)
        .where(ReviewSession.report_id == report_id)
        .order_by(ReviewSession.created_at.desc())
    )
    result = await db.execute(query)
    sessions = result.scalars().all()

    return {
        "items": [
            {
                "id": s.id,
                "is_active": s.is_active,
                "focused_finding_id": s.focused_finding_id,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                "message_count": 0,
            }
            for s in sessions
        ],
        "total": len(sessions),
    }


@router.get("/sessions/{session_id}", response_model=ReviewSessionResponse)
async def get_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取 Review 会话详情"""
    query = (
        select(ReviewSession)
        .options(
            selectinload(ReviewSession.messages),
            selectinload(ReviewSession.actions),
        )
        .where(ReviewSession.id == session_id)
    )

    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"会话不存在: {session_id}"
        )

    return _session_to_response(session)


@router.post("/sessions/{session_id}/focus")
async def focus_finding(
    session_id: str,
    request: FocusRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """聚焦到某个漏洞"""
    # 获取会话
    query = (
        select(ReviewSession)
        .options(selectinload(ReviewSession.report))
        .where(ReviewSession.id == session_id)
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"会话不存在: {session_id}"
        )

    if not session.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="会话已关闭"
        )

    # 验证漏洞存在 (支持嵌套结构)
    report = session.report
    finding = None
    for f in (report.findings or []):
        fid = f.get("id") or f.get("original_finding", {}).get("id")
        if fid == request.finding_id:
            finding = f
            break

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"漏洞不存在: {request.finding_id}"
        )

    # 更新聚焦
    session.focused_finding_id = request.finding_id

    # 提取标题和严重性 (支持嵌套)
    orig = finding.get("original_finding", finding)
    title = orig.get("title", "未知")
    severity = finding.get("final_severity") or orig.get("severity", "未知")

    # 添加系统消息
    system_msg = ReviewMessage(
        session_id=session.id,
        role="system",
        content=f"切换聚焦到漏洞: {title}\n严重性: {severity}",
    )
    db.add(system_msg)

    await db.flush()

    return {"success": True, "focused_finding_id": request.finding_id}


@router.post("/sessions/{session_id}/chat", response_model=ChatResponse)
async def chat(
    session_id: str,
    request: ChatRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    发送聊天消息，通过 LLM 提供智能安全分析
    """
    # 获取会话
    query = (
        select(ReviewSession)
        .options(
            selectinload(ReviewSession.report),
            selectinload(ReviewSession.messages),
        )
        .where(ReviewSession.id == session_id)
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"会话不存在: {session_id}"
        )

    if not session.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="会话已关闭"
        )

    # 保存用户消息
    user_msg = ReviewMessage(
        session_id=session.id,
        role="user",
        content=request.message,
    )
    db.add(user_msg)

    # 获取当前聚焦漏洞的上下文 (优先用请求中的 finding_id)
    target_finding_id = request.finding_id or session.focused_finding_id
    finding = None
    if target_finding_id:
        for f in (session.report.findings or []):
            # 支持嵌套结构 (original_finding.id) 和扁平结构 (id)
            fid = f.get("id") or f.get("original_finding", {}).get("id")
            if fid == target_finding_id:
                # 提取 original_finding 内容 (agent 需要扁平字段)
                if "original_finding" in f:
                    finding = {**f["original_finding"]}
                    # 补充验证阶段的额外信息
                    if f.get("final_severity"):
                        finding["severity"] = f["final_severity"]
                    if f.get("verification_status"):
                        finding["verification_status"] = f["verification_status"]
                    if f.get("code_context"):
                        finding["code_context"] = f["code_context"]
                else:
                    finding = f
                break

    # 获取项目路径 → 初始化 ReviewAgent
    try:
        project_path, project_id = await _get_project_path(session.report, db)
        agent = _get_review_agent(project_path, project_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ReviewAgent 初始化失败: {e}")
        # Fallback: 返回错误提示
        ai_content = f"ReviewAgent 初始化失败: {str(e)}\n请检查项目文件路径和 LLM API 配置。"
        ai_msg = ReviewMessage(session_id=session.id, role="assistant", content=ai_content)
        db.add(ai_msg)
        await db.flush()
        await db.refresh(ai_msg)
        return ChatResponse(message_id=ai_msg.id, content=ai_content)

    # 设置漏洞上下文
    agent.set_finding_context(finding)

    # 构建历史消息
    history_messages = [
        {"role": m.role, "content": m.content}
        for m in (session.messages or [])
        if m.role in ("user", "assistant")
    ]

    # 调用 ReviewAgent（在线程池中执行同步调用）
    try:
        ai_content = await asyncio.to_thread(
            agent.chat_sync, request.message, history_messages
        )
    except Exception as e:
        logger.error(f"ReviewAgent 调用失败: {e}")
        ai_content = f"AI 分析暂时不可用: {str(e)}"

    # 保存 AI 回复
    ai_msg = ReviewMessage(
        session_id=session.id,
        role="assistant",
        content=ai_content,
    )
    db.add(ai_msg)

    await db.flush()
    await db.refresh(ai_msg)

    return ChatResponse(
        message_id=ai_msg.id,
        content=ai_content,
        suggested_actions=["confirm", "reject", "downgrade"] if session.focused_finding_id else None,
    )


@router.post("/sessions/{session_id}/chat/stream")
async def chat_stream(
    session_id: str,
    request: ChatRequest,
    user: User = Depends(get_current_user),
):
    """
    流式聊天 - 通过 SSE 发送 AI 分析进度和最终结果

    注意: 不使用 Depends(get_db)，避免 SQLite 单写阻塞其他请求。
    使用短生命周期 session 代替。

    事件类型:
    - thinking: AI 正在思考/分析
    - tool_call: AI 正在调用工具 (搜索代码、获取函数等)
    - complete: 分析完成
    - response: 最终完整回复
    - error: 出错
    """
    session_factory = _get_session_factory()

    # 1. 短生命周期 session: 加载数据 + 保存用户消息
    async with session_factory() as db:
        query = (
            select(ReviewSession)
            .options(
                selectinload(ReviewSession.report),
                selectinload(ReviewSession.messages),
            )
            .where(ReviewSession.id == session_id)
        )
        result = await db.execute(query)
        session = result.scalar_one_or_none()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"会话不存在: {session_id}"
            )

        if not session.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="会话已关闭"
            )

        # 保存用户消息
        user_msg = ReviewMessage(
            session_id=session.id,
            role="user",
            content=request.message,
        )
        db.add(user_msg)
        await db.commit()

        # 提取需要的数据 (session 关闭后 ORM 对象不可用)
        sess_id = session.id
        # 优先使用请求中的 finding_id, 否则使用 session 的
        focused_finding_id = request.finding_id or session.focused_finding_id
        report_findings = session.report.findings if session.report else []
        report_audit_id = session.report.audit_id if session.report else None
        history_messages = [
            {"role": m.role, "content": m.content}
            for m in (session.messages or [])
            if m.role in ("user", "assistant")
        ]

    # 2. 提取漏洞上下文 (不需要 DB)
    finding = None
    if focused_finding_id:
        for f in (report_findings or []):
            fid = f.get("id") or f.get("original_finding", {}).get("id")
            if fid == focused_finding_id:
                if "original_finding" in f:
                    finding = {**f["original_finding"]}
                    if f.get("final_severity"):
                        finding["severity"] = f["final_severity"]
                    if f.get("verification_status"):
                        finding["verification_status"] = f["verification_status"]
                    if f.get("code_context"):
                        finding["code_context"] = f["code_context"]
                else:
                    finding = f
                break

    # 3. 获取项目路径 (短生命周期 session, 快速查询不阻塞)
    try:
        async with session_factory() as db2:
            audit_query = (
                select(Audit)
                .options(selectinload(Audit.project))
                .where(Audit.id == report_audit_id)
            )
            audit_result = await db2.execute(audit_query)
            audit = audit_result.scalar_one_or_none()
            if not audit or not audit.project:
                raise HTTPException(status_code=500, detail="无法获取项目信息")
            project_path = audit.project.source_path
            project_id = audit.project.id
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取项目信息失败: {e}")
        async def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'content': f'获取项目信息失败: {str(e)}'}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(error_stream(), media_type="text/event-stream")

    # 4. 创建进度队列 (agent 初始化和 chat 都在后台线程中完成)
    progress_queue = queue.Queue()
    result_container = {"content": None, "error": None}

    def run_agent():
        agent = None
        try:
            # 初始化 agent (首次需要索引项目，后续走缓存)
            if project_id not in _project_agents:
                progress_queue.put({"type": "thinking", "content": "正在初始化项目索引..."})
            agent = _get_review_agent(project_path, project_id)

            # 设置上下文
            agent.set_finding_context(finding)
            agent.set_progress_queue(progress_queue)

            progress_queue.put({"type": "thinking", "content": "正在分析..."})
            result_container["content"] = agent.chat_sync(request.message, history_messages)
        except Exception as e:
            result_container["error"] = str(e)
        finally:
            if agent:
                agent.set_progress_queue(None)
            progress_queue.put({"type": "_done", "content": ""})

    async def event_generator():
        loop = asyncio.get_event_loop()
        task = loop.run_in_executor(None, run_agent)

        while True:
            try:
                event = progress_queue.get_nowait()
                if event["type"] == "_done":
                    break
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            except queue.Empty:
                if task.done():
                    while not progress_queue.empty():
                        event = progress_queue.get_nowait()
                        if event["type"] != "_done":
                            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    break
                await asyncio.sleep(0.1)

        await task

        # 发送最终响应
        if result_container["error"]:
            ai_content = f"AI 分析暂时不可用: {result_container['error']}"
            yield f"data: {json.dumps({'type': 'error', 'content': ai_content}, ensure_ascii=False)}\n\n"
        else:
            ai_content = result_container["content"] or ""
            yield f"data: {json.dumps({'type': 'response', 'content': ai_content}, ensure_ascii=False)}\n\n"

        # 短生命周期 session: 保存 AI 回复
        try:
            async with session_factory() as save_db:
                ai_msg = ReviewMessage(
                    session_id=sess_id,
                    role="assistant",
                    content=ai_content,
                )
                save_db.add(ai_msg)
                await save_db.flush()
                await save_db.refresh(ai_msg)
                yield f"data: {json.dumps({'type': 'message_id', 'content': ai_msg.id}, ensure_ascii=False)}\n\n"
                await save_db.commit()
        except Exception as e:
            logger.error(f"保存 AI 回复失败: {e}")

        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/sessions/{session_id}/actions")
async def apply_action(
    session_id: str,
    request: ReviewActionRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    执行 Review 操作

    - **confirm**: 确认漏洞有效
    - **reject**: 驳回漏洞（误报）
    - **downgrade**: 降级严重性
    - **upgrade**: 升级严重性
    - **add_note**: 添加备注
    """
    # 获取会话和报告
    query = (
        select(ReviewSession)
        .options(selectinload(ReviewSession.report))
        .where(ReviewSession.id == session_id)
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"会话不存在: {session_id}"
        )

    if not session.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="会话已关闭"
        )

    report = session.report

    # 查找漏洞
    finding_idx = None
    finding = None
    for idx, f in enumerate(report.findings or []):
        if f.get("id") == request.finding_id:
            finding_idx = idx
            finding = f
            break

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"漏洞不存在: {request.finding_id}"
        )

    # 记录原值
    from_value = finding.get("severity") if request.action_type in ["downgrade", "upgrade"] else finding.get("status")
    to_value = None

    # 执行操作
    if request.action_type == "confirm":
        finding["status"] = "confirmed"
        to_value = "confirmed"

    elif request.action_type == "reject":
        finding["status"] = "rejected"
        to_value = "rejected"

    elif request.action_type == "downgrade":
        if not request.new_severity:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="降级操作需要指定 new_severity"
            )
        finding["severity"] = request.new_severity.value
        to_value = request.new_severity.value

    elif request.action_type == "upgrade":
        if not request.new_severity:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="升级操作需要指定 new_severity"
            )
        finding["severity"] = request.new_severity.value
        to_value = request.new_severity.value

    elif request.action_type == "add_note":
        if "review_notes" not in finding:
            finding["review_notes"] = []
        finding["review_notes"].append({
            "content": request.reason,
            "created_at": utc_now().isoformat(),
        })
        to_value = "note_added"

    # 更新报告
    report.findings[finding_idx] = finding

    # 记录操作
    action = ReviewAction(
        session_id=session.id,
        finding_id=request.finding_id,
        action_type=ReviewActionType(request.action_type.value),
        from_value=from_value,
        to_value=to_value,
        reason=request.reason,
    )
    db.add(action)

    await db.flush()
    await db.refresh(action)

    return {
        "success": True,
        "action_id": action.id,
        "finding_id": request.finding_id,
        "action_type": request.action_type,
        "from_value": from_value,
        "to_value": to_value,
    }


@router.post("/sessions/{session_id}/close")
async def close_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """关闭 Review 会话"""
    query = select(ReviewSession).where(ReviewSession.id == session_id)
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"会话不存在: {session_id}"
        )

    session.is_active = False
    await db.flush()

    return {"success": True, "session_id": session_id, "status": "closed"}


# =============================================================================
# 会话历史管理
# =============================================================================

@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """删除 Review 会话（包括其所有消息和操作）"""
    query = (
        select(ReviewSession)
        .options(
            selectinload(ReviewSession.messages),
            selectinload(ReviewSession.actions),
        )
        .where(ReviewSession.id == session_id)
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"会话不存在: {session_id}"
        )

    await db.delete(session)
    await db.flush()

    return {"success": True, "session_id": session_id}


# =============================================================================
# 漏洞标记 API
# =============================================================================

@router.get("/marks/{report_id}")
async def get_marks(
    report_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取报告的所有漏洞标记"""
    query = select(FindingMark).where(FindingMark.report_id == report_id)
    result = await db.execute(query)
    marks = result.scalars().all()

    return {
        "items": {
            m.finding_id: {
                "id": m.id,
                "finding_id": m.finding_id,
                "mark_type": m.mark_type.value if m.mark_type else None,
                "severity": m.severity,
                "note": m.note,
                "updated_at": m.updated_at.isoformat() if m.updated_at else None,
            }
            for m in marks
        }
    }


@router.post("/marks/{report_id}")
async def save_mark(
    report_id: str,
    data: dict,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """创建或更新漏洞标记"""
    finding_id = data.get("finding_id")
    mark_type = data.get("mark_type")
    severity = data.get("severity")
    note = data.get("note", "")

    if not finding_id or not mark_type:
        raise HTTPException(status_code=400, detail="finding_id 和 mark_type 必填")

    if mark_type not in [e.value for e in FindingMarkType]:
        raise HTTPException(status_code=400, detail=f"无效的 mark_type: {mark_type}")

    # 查找是否已有标记
    query = select(FindingMark).where(
        FindingMark.report_id == report_id,
        FindingMark.finding_id == finding_id,
    )
    result = await db.execute(query)
    existing = result.scalar_one_or_none()

    if existing:
        existing.mark_type = FindingMarkType(mark_type)
        existing.severity = severity
        existing.note = note
        existing.updated_at = utc_now()
        mark = existing
    else:
        mark = FindingMark(
            report_id=report_id,
            finding_id=finding_id,
            mark_type=FindingMarkType(mark_type),
            severity=severity,
            note=note,
        )
        db.add(mark)

    await db.flush()

    return {
        "id": mark.id,
        "finding_id": mark.finding_id,
        "mark_type": mark.mark_type.value,
        "severity": mark.severity,
        "note": mark.note,
    }


@router.delete("/marks/{report_id}/{finding_id}")
async def delete_mark(
    report_id: str,
    finding_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """删除漏洞标记"""
    query = select(FindingMark).where(
        FindingMark.report_id == report_id,
        FindingMark.finding_id == finding_id,
    )
    result = await db.execute(query)
    mark = result.scalar_one_or_none()

    if not mark:
        raise HTTPException(status_code=404, detail="标记不存在")

    await db.delete(mark)
    await db.flush()

    return {"success": True}


# =============================================================================
# AI 提取结构化漏洞
# =============================================================================

_EXTRACT_FINDING_PROMPT = """你是一个安全审计专家。根据以下 AI 分析内容，提取出结构化的漏洞信息。

请以 JSON 格式返回，包含以下字段：
- title: 漏洞标题（简洁描述核心问题，15字以内）
- severity: 严重性级别（CRITICAL / HIGH / MEDIUM / LOW / ADVISORY）
- category: 漏洞类别（如 logic, access_control, overflow, type_confusion, reentrancy, flash_loan 等）
- location: 漏洞位置，格式为 "module::function"（如 "challenge::claim_drop"）
- description: 漏洞描述（100-300字，说明问题本质、原因和影响）
- proof: 漏洞证明（简要说明为什么这是漏洞，代码中缺失了什么检查）
- attack_scenario: 攻击场景（分步骤描述攻击者如何利用此漏洞）
- code_snippet: 相关漏洞代码片段（从分析中提取关键代码）
- recommendation: 修复建议（具体可操作的修复方案，最好包含代码示例）

仅返回 JSON，不要其他内容。

AI 分析内容：
{analysis}
"""


@router.post("/extract-finding")
async def extract_finding(data: dict, user: User = Depends(get_current_user)):
    """
    从 AI 分析内容中提取结构化漏洞信息
    使用 LLM 按模板格式化
    """
    analysis = data.get("analysis", "")
    if not analysis or len(analysis) < 20:
        raise HTTPException(status_code=400, detail="分析内容过短")

    try:
        from ...config import get_agent_configs
        from ...agents.base_agent import AgentConfig
        from ...llm_providers import LLMProviderFactory, LLMConfig, ProviderType

        configs = get_agent_configs("auto")
        agent_config = configs.get("review") or AgentConfig(
            provider="dashscope", model="qwen-plus", max_tokens=4096
        )

        # 构建 LLMConfig
        provider_name = (agent_config.provider or "dashscope").lower()
        model_name = agent_config.model or agent_config.model_name or "qwen-plus"
        llm_config = LLMConfig(
            provider=ProviderType(provider_name),
            model=model_name,
            temperature=0.1,
            max_tokens=2000,
        )
        provider = LLMProviderFactory.create(llm_config)

        prompt = _EXTRACT_FINDING_PROMPT.format(analysis=analysis[:3000])

        response = await asyncio.to_thread(
            provider.chat,
            [{"role": "user", "content": prompt}],
        )

        # response 是 LLMResponse 对象，取 .content
        content = response.content.strip()
        # 去除可能的 markdown 代码块标记
        if content.startswith("```"):
            content = content.split("\n", 1)[1] if "\n" in content else content[3:]
        if content.endswith("```"):
            content = content[:-3]
        if content.startswith("json"):
            content = content[4:]
        content = content.strip()

        import json as _json
        finding = _json.loads(content)

        # 确保必要字段
        finding.setdefault("title", "未命名漏洞")
        finding.setdefault("severity", "MEDIUM")
        finding.setdefault("category", "security")
        finding.setdefault("location", "")
        finding.setdefault("description", analysis[:300])
        finding.setdefault("proof", "")
        finding.setdefault("attack_scenario", "")
        finding.setdefault("code_snippet", "")
        finding.setdefault("recommendation", "")

        # 归一化：LLM 可能返回 list 类型，统一转为字符串
        for key in ("description", "proof", "attack_scenario", "code_snippet", "recommendation"):
            if isinstance(finding.get(key), list):
                finding[key] = "\n".join(str(item) for item in finding[key])

        return finding

    except Exception as e:
        logger.error(f"提取漏洞信息失败: {e}", exc_info=True)
        # 降级：返回基本结构，让用户编辑
        return {
            "title": "从 AI 分析发现的漏洞",
            "severity": "HIGH",
            "category": "security",
            "location": "",
            "description": analysis[:500],
            "proof": "",
            "attack_scenario": "",
            "code_snippet": "",
            "recommendation": "",
            "error": str(e),
        }
