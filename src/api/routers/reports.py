"""
报告查询 API 路由
"""
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from pydantic import BaseModel

from ..auth.dependencies import get_current_user
from ...storage.database import get_db, Report, Audit, FindingMark, User, UserRole


router = APIRouter(prefix="/reports", tags=["reports"])


def _check_report_owner(report: Report, user: User):
    """检查报告所有权（通过关联审计任务的 owner_id）"""
    if user.role == UserRole.ADMIN:
        return
    if report.audit and report.audit.owner_id and report.audit.owner_id != user.id:
        raise HTTPException(status_code=403, detail="无权访问该报告")


class FindingResponse(BaseModel):
    """漏洞响应"""
    id: str
    title: str
    severity: str
    status: str
    category: str
    description: str
    location: Optional[dict] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    spec_coverage: Optional[str] = None
    proof: Optional[str] = None           # 漏洞证明
    attack_scenario: Optional[str] = None # 攻击场景


class ReportResponse(BaseModel):
    """报告响应"""
    id: str
    audit_id: str
    project_name: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    advisory_count: int
    findings: List[FindingResponse]
    summary: dict
    report_path: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """报告列表响应"""
    total: int
    items: List[ReportResponse]


def _parse_finding(f: dict) -> dict:
    """
    解析 VerifiedFinding 序列化后的结构，转换为前端期望的格式

    输入结构:
    {
        "original_finding": {
            "id", "title", "severity",
            "location": { "module": "xxx", "function": "yyy", "code_snippet": "..." },
            "_phase2_func_context": { "function_code": "..." }
        },
        "verification_status": "confirmed",
        "final_severity": "HIGH",
        ...
    }

    输出结构:
    {
        "id": "...",
        "title": "...",
        "severity": "HIGH",
        "status": "confirmed",
        "location": { "file": "module::function", "line_start": 1, "line_end": 1 },
        "code_snippet": "...",
        ...
    }
    """
    original = f.get("original_finding", f)

    # 获取验证状态作为 status
    verification_status = f.get("verification_status", "open")
    status_map = {
        "confirmed": "confirmed",
        "false_positive": "rejected",
        "needs_review": "open",
        "partially_valid": "open"
    }
    finding_status = status_map.get(verification_status, "open")

    # 严重性：优先使用 final_severity，否则使用 original 中的 severity
    _VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "ADVISORY"}
    severity = f.get("final_severity") or original.get("severity") or "MEDIUM"
    severity = severity.upper() if isinstance(severity, str) else "MEDIUM"
    if severity not in _VALID_SEVERITIES:
        severity = "MEDIUM"

    # 转换 location 格式：{ module, function } -> { file, line_start, line_end }
    raw_location = original.get("location", f.get("location"))
    location = None
    if raw_location:
        if isinstance(raw_location, dict):
            # 新格式：{ module: "xxx", function: "yyy" }
            module_name = raw_location.get("module", "")
            func_name = raw_location.get("function", "")
            if module_name or func_name:
                location = {
                    "file": f"{module_name}::{func_name}" if module_name else func_name,
                    "line_start": 1,
                    "line_end": 1
                }
        elif isinstance(raw_location, str):
            # 字符串格式
            location = {
                "file": raw_location,
                "line_start": 1,
                "line_end": 1
            }

    # 提取代码片段：优先从 _phase2_func_context 获取完整代码
    code_snippet = None
    func_context = original.get("_phase2_func_context", {})
    if func_context and func_context.get("function_code"):
        code_snippet = func_context.get("function_code")
    elif raw_location and isinstance(raw_location, dict):
        code_snippet = raw_location.get("code_snippet")
    if not code_snippet:
        code_snippet = original.get("code_snippet", f.get("code_snippet"))

    def _to_str(val) -> Optional[str]:
        """将可能是 list 的值转为字符串"""
        if val is None:
            return None
        if isinstance(val, list):
            return "\n".join(str(item) for item in val)
        return str(val)

    return {
        "id": original.get("id", f.get("id", "")),
        "title": original.get("title", f.get("title", "")),
        "severity": severity,
        "status": finding_status,
        "category": original.get("category", f.get("category", "")),
        "description": _to_str(original.get("description", f.get("description", ""))),
        "location": location,
        "code_snippet": _to_str(code_snippet),
        "recommendation": _to_str(original.get("recommendation", f.get("recommendation"))),
        "spec_coverage": f.get("spec_coverage"),
        # 额外字段供详情页使用
        "proof": _to_str(original.get("proof")),
        "attack_scenario": _to_str(original.get("attack_scenario")),
    }


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ADVISORY": 4}


def _report_to_response(report: Report) -> ReportResponse:
    """将 ORM 对象转换为响应模型"""
    project_name = "Unknown"
    if report.audit and report.audit.project:
        project_name = report.audit.project.name

    # 解析 findings，排除已驳回的
    findings = []
    for f in (report.findings or []):
        parsed = _parse_finding(f)
        if parsed.get("status") == "rejected":
            continue
        findings.append(FindingResponse(
            id=parsed["id"],
            title=parsed["title"],
            severity=parsed["severity"],
            status=parsed["status"],
            category=parsed["category"],
            description=parsed["description"],
            location=parsed.get("location"),
            code_snippet=parsed.get("code_snippet"),
            recommendation=parsed.get("recommendation"),
            spec_coverage=parsed.get("spec_coverage"),
            proof=parsed.get("proof"),
            attack_scenario=parsed.get("attack_scenario"),
        ))

    # 按严重性排序: CRITICAL > HIGH > MEDIUM > LOW > ADVISORY
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity.upper(), 99))

    # 从过滤后的列表计算统计（排除已驳回的）
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "ADVISORY": 0}
    for f in findings:
        sev = f.severity.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    return ReportResponse(
        id=report.id,
        audit_id=report.audit_id,
        project_name=project_name,
        total_findings=len(findings),
        critical_count=severity_counts["CRITICAL"],
        high_count=severity_counts["HIGH"],
        medium_count=severity_counts["MEDIUM"],
        low_count=severity_counts["LOW"],
        advisory_count=severity_counts["ADVISORY"],
        findings=findings,
        summary=report.summary or {},
        report_path=report.report_path,
        created_at=report.created_at,
    )


@router.get("", response_model=ReportListResponse)
async def list_reports(
    skip: int = 0,
    limit: int = 20,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取报告列表"""
    limit = min(limit, 100)

    query = (
        select(Report)
        .join(Report.audit)
        .options(
            selectinload(Report.audit).selectinload(Audit.project)
        )
        .order_by(Report.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    if user.role != UserRole.ADMIN:
        query = query.where(Audit.owner_id == user.id)

    result = await db.execute(query)
    reports = result.scalars().all()

    # 总数查询简化
    total = len(reports)  # TODO: 正确的 count 查询

    return ReportListResponse(
        total=total,
        items=[_report_to_response(r) for r in reports]
    )


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取报告详情"""
    query = (
        select(Report)
        .options(
            selectinload(Report.audit).selectinload(Audit.project)
        )
        .where(Report.id == report_id)
    )

    result = await db.execute(query)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"报告不存在: {report_id}"
        )
    _check_report_owner(report, user)

    return _report_to_response(report)


@router.get("/{report_id}/findings")
async def get_report_findings(
    report_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取报告中的漏洞列表"""
    query = select(Report).options(selectinload(Report.audit)).where(Report.id == report_id)
    result = await db.execute(query)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail=f"报告不存在: {report_id}")
    _check_report_owner(report, user)

    # 解析并转换 findings 结构
    raw_findings = report.findings or []
    parsed_findings = [_parse_finding(f) for f in raw_findings]

    # 按条件过滤
    if severity:
        severity_upper = severity.upper()
        parsed_findings = [f for f in parsed_findings if f.get("severity", "").upper() == severity_upper]
    if status:
        parsed_findings = [f for f in parsed_findings if f.get("status") == status]
    else:
        # 默认排除已驳回的漏洞
        parsed_findings = [f for f in parsed_findings if f.get("status") != "rejected"]

    # 按严重性排序: CRITICAL > HIGH > MEDIUM > LOW > ADVISORY
    parsed_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "").upper(), 99))

    return {
        "report_id": report_id,
        "total": len(parsed_findings),
        "items": parsed_findings
    }


@router.get("/{report_id}/findings/{finding_id}")
async def get_finding(
    report_id: str,
    finding_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取单个漏洞详情"""
    query = select(Report).options(selectinload(Report.audit)).where(Report.id == report_id)
    result = await db.execute(query)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"报告不存在: {report_id}"
        )
    _check_report_owner(report, user)

    # 查找漏洞
    for finding in (report.findings or []):
        if finding.get("id") == finding_id:
            return finding

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"漏洞不存在: {finding_id}"
    )


@router.get("/{report_id}/export")
async def export_report(
    report_id: str,
    format: str = "markdown",
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    导出报告

    - **format**: 导出格式 (markdown, json)
    """
    query = (
        select(Report)
        .options(
            selectinload(Report.audit).selectinload(Audit.project)
        )
        .where(Report.id == report_id)
    )

    result = await db.execute(query)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"报告不存在: {report_id}"
        )
    _check_report_owner(report, user)

    # 加载漏洞标记
    marks_query = select(FindingMark).where(FindingMark.report_id == report_id)
    marks_result = await db.execute(marks_query)
    marks_list = marks_result.scalars().all()
    marks_map = {m.finding_id: m for m in marks_list}

    MARK_LABELS = {
        "issue": "是问题",
        "not_issue": "不是问题",
        "legacy": "遗留问题",
    }

    if format == "json":
        resp = _report_to_response(report)
        # 附加标记信息
        resp["marks"] = {
            m.finding_id: {
                "mark_type": m.mark_type.value if m.mark_type else None,
                "severity": m.severity,
                "note": m.note,
            }
            for m in marks_list
        }
        return resp

    # Markdown 格式
    project_name = "Unknown"
    if report.audit and report.audit.project:
        project_name = report.audit.project.name

    # 统计标记情况
    issue_count = sum(1 for m in marks_list if m.mark_type and m.mark_type.value == "issue")
    not_issue_count = sum(1 for m in marks_list if m.mark_type and m.mark_type.value == "not_issue")
    legacy_count = sum(1 for m in marks_list if m.mark_type and m.mark_type.value == "legacy")
    unmarked_count = len(report.findings or []) - len(marks_list)

    md_content = f"""# 安全审计报告

## 项目信息

- **项目名称**: {project_name}
- **报告 ID**: {report.id}
- **风险评分**: {report.risk_score}

## 漏洞统计

| 级别 | 数量 |
|------|------|
| Critical | {report.critical_count} |
| High | {report.high_count} |
| Medium | {report.medium_count} |
| Low | {report.low_count} |
| Advisory | {report.advisory_count} |
| **总计** | **{report.total_findings}** |

## 审计标记统计

| 标记 | 数量 |
|------|------|
| 是问题 | {issue_count} |
| 不是问题 | {not_issue_count} |
| 遗留问题 | {legacy_count} |
| 未标记 | {unmarked_count} |

## 漏洞详情

"""

    for i, finding in enumerate(report.findings or [], 1):
        finding_id = finding.get('id', '')
        mark = marks_map.get(finding_id)
        mark_label = ""
        if mark and mark.mark_type:
            mark_label = f" [{MARK_LABELS.get(mark.mark_type.value, mark.mark_type.value)}]"

        md_content += f"""
### {i}. {finding.get('title', 'Unknown')}{mark_label}

- **严重性**: {finding.get('severity', 'unknown')}
- **类别**: {finding.get('category', 'unknown')}
- **状态**: {finding.get('status', 'open')}
"""
        if mark and mark.mark_type:
            md_content += f"- **审计标记**: {MARK_LABELS.get(mark.mark_type.value, mark.mark_type.value)}\n"
            if mark.note:
                md_content += f"- **审计备注**: {mark.note}\n"

        md_content += f"""
**描述**:
{finding.get('description', 'N/A')}

**建议**:
{finding.get('recommendation', 'N/A')}

---
"""

    return {
        "format": "markdown",
        "content": md_content
    }


@router.delete("/{report_id}")
async def delete_report(
    report_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """删除报告"""
    query = select(Report).options(selectinload(Report.audit)).where(Report.id == report_id)
    result = await db.execute(query)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"报告不存在: {report_id}"
        )
    _check_report_owner(report, user)

    # 删除关联的漏洞标记
    marks_query = select(FindingMark).where(FindingMark.report_id == report_id)
    marks_result = await db.execute(marks_query)
    for mark in marks_result.scalars().all():
        await db.delete(mark)

    await db.delete(report)
    await db.flush()

    return {"detail": "报告已删除"}


@router.post("/{report_id}/findings")
async def add_finding(
    report_id: str,
    data: dict,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    手动添加漏洞到报告（从 AI Review 对话中发现的漏洞）
    """
    import uuid as _uuid

    query = select(Report).options(selectinload(Report.audit)).where(Report.id == report_id)
    result = await db.execute(query)
    report = result.scalar_one_or_none()

    if not report:
        raise HTTPException(status_code=404, detail=f"报告不存在: {report_id}")
    _check_report_owner(report, user)

    # 构建新 finding
    finding_id = data.get("id") or str(_uuid.uuid4())[:12]
    new_finding = {
        "id": finding_id,
        "title": data.get("title", "未命名漏洞"),
        "severity": data.get("severity", "MEDIUM").upper(),
        "status": "confirmed",
        "verification_status": "confirmed",  # 确保 _parse_finding 映射为 confirmed
        "category": data.get("category", "security"),
        "description": data.get("description", ""),
        "location": data.get("location"),
        "code_snippet": data.get("code_snippet"),
        "recommendation": data.get("recommendation"),
        "proof": data.get("proof"),
        "attack_scenario": data.get("attack_scenario"),
        "source": "manual_review",  # 标记来源为人工review
    }

    # 更新 findings 列表
    findings = list(report.findings or [])
    findings.append(new_finding)
    report.findings = findings

    # 标记 JSON 列已修改，确保 SQLAlchemy 检测到变更
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(report, 'findings')

    # 更新统计
    report.total_findings = len(findings)
    severity_key = new_finding["severity"].lower()
    severity_count_map = {
        "critical": "critical_count",
        "high": "high_count",
        "medium": "medium_count",
        "low": "low_count",
        "advisory": "advisory_count",
    }
    count_field = severity_count_map.get(severity_key)
    if count_field:
        setattr(report, count_field, (getattr(report, count_field, 0) or 0) + 1)

    await db.flush()

    return {
        "id": finding_id,
        "title": new_finding["title"],
        "severity": new_finding["severity"],
        "status": "confirmed",
    }
