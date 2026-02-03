"""
Multi-Agent Security Scan CLI

基于多Agent系统的智能合约安全扫描工具。

Usage:
    # 扫描单个文件
    python -m src.cli.security_scan --file ./sources/pool.move

    # 扫描整个项目
    python -m src.cli.security_scan --project ./my-move-project

    # 完整模式 (BA + TA + 角色交换)
    python -m src.cli.security_scan --project ./my-project --full

    # 快速模式 (仅BA)
    python -m src.cli.security_scan --project ./my-project --quick
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# 确保可以导入项目模块
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.agents import (
    SecurityAuditEngine,
    AuditConfig,
    AuditResult,
)
from src.agents.base_agent import AgentConfig


def read_move_files(project_path: str) -> str:
    """读取项目中的所有Move文件"""
    code_parts = []
    project = Path(project_path)

    # 查找sources目录
    sources_dir = project / "sources"
    if not sources_dir.exists():
        # 尝试直接在项目根目录找.move文件
        sources_dir = project

    for move_file in sources_dir.rglob("*.move"):
        relative_path = move_file.relative_to(project)
        code_parts.append(f"// ============ {relative_path} ============")
        code_parts.append(move_file.read_text(encoding="utf-8"))
        code_parts.append("")

    return "\n".join(code_parts)


def read_single_file(file_path: str) -> str:
    """读取单个Move文件"""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    return path.read_text(encoding="utf-8")


async def run_security_scan(
    code: str,
    project_name: str,
    mode: str = "full",
    output_dir: Optional[str] = None,
    verbose: bool = False,
    project_path: Optional[str] = None,  # 🔥 新增：项目路径，启用本地上下文系统
) -> AuditResult:
    """
    运行安全扫描

    Args:
        code: Move源代码
        project_name: 项目名称
        mode: 扫描模式 (full, quick, targeted)
        output_dir: 输出目录
        verbose: 详细输出
        project_path: 项目路径 (启用本地调用图和上下文检索)

    Returns:
        审计结果
    """
    # 根据模式配置
    # 🔥 如果提供了 project_path，启用本地上下文系统
    enable_context = project_path is not None

    if mode == "quick":
        config = AuditConfig(
            enable_broad_analysis=True,
            enable_targeted_analysis=False,
            enable_role_swap=False,
            enable_context_system=enable_context,
            output_dir=output_dir or "reports/security_audits",
        )
    elif mode == "targeted":
        config = AuditConfig(
            enable_broad_analysis=False,
            enable_targeted_analysis=True,
            enable_role_swap=False,
            enable_context_system=enable_context,
            output_dir=output_dir or "reports/security_audits",
        )
    else:  # full
        config = AuditConfig(
            enable_broad_analysis=True,
            enable_targeted_analysis=True,
            enable_role_swap=True,
            enable_context_system=enable_context,
            output_dir=output_dir or "reports/security_audits",
        )

    # Agent配置
    agent_config = AgentConfig(
        temperature=0.1 if mode == "quick" else 0.3,
        max_tokens=4096,
    )

    # 创建引擎并运行
    engine = SecurityAuditEngine(config=config, agent_config=agent_config)
    result = await engine.audit(code, project_name, project_path=project_path)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Multi-Agent Security Scan - 多Agent智能合约安全扫描",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    # 扫描单个文件
    python -m src.cli.security_scan --file ./sources/pool.move

    # 扫描整个项目 (完整模式)
    python -m src.cli.security_scan --project ./my-move-project --full

    # 快速扫描 (仅BA模式)
    python -m src.cli.security_scan --project ./my-project --quick

    # 针对性扫描 (仅TA模式)
    python -m src.cli.security_scan --project ./my-project --targeted

    # 指定输出目录
    python -m src.cli.security_scan --project ./my-project --output ./my-reports
        """,
    )

    # 输入源
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--file", "-f",
        help="扫描单个Move文件",
    )
    input_group.add_argument(
        "--project", "-p",
        help="扫描整个项目目录",
    )

    # 扫描模式
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--full",
        action="store_true",
        default=True,
        help="完整模式: BA + TA + 角色交换验证 (默认)",
    )
    mode_group.add_argument(
        "--quick", "-q",
        action="store_true",
        help="快速模式: 仅BA广泛分析",
    )
    mode_group.add_argument(
        "--targeted", "-t",
        action="store_true",
        help="针对模式: 仅TA针对性检测",
    )

    # 输出选项
    parser.add_argument(
        "--output", "-o",
        help="输出目录 (默认: reports/security_audits)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="不生成报告文件",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="只生成JSON报告",
    )

    # 其他选项
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="详细输出",
    )
    parser.add_argument(
        "--name", "-n",
        help="项目名称 (默认从路径推断)",
    )

    args = parser.parse_args()

    # 确定扫描模式
    if args.quick:
        mode = "quick"
    elif args.targeted:
        mode = "targeted"
    else:
        mode = "full"

    # 读取代码
    project_path = None  # 🔥 项目路径 (用于本地上下文系统)
    try:
        if args.file:
            code = read_single_file(args.file)
            project_name = args.name or Path(args.file).stem
            # 单文件模式不启用上下文系统
        else:
            code = read_move_files(args.project)
            project_name = args.name or Path(args.project).name
            # 🔥 项目模式：获取绝对路径，启用本地上下文系统
            project_path = str(Path(args.project).resolve())

        if not code.strip():
            print("[ERROR] 未找到Move代码")
            return 1

    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        return 1

    # 打印启动信息
    print("=" * 60)
    print("Multi-Agent Security Scan")
    print("=" * 60)
    print(f"项目: {project_name}")
    print(f"模式: {mode}")
    print(f"代码行数: {len(code.splitlines())}")
    if project_path:
        print(f"上下文系统: ✅ 启用 (本地调用图 + 智能检索)")
    else:
        print(f"上下文系统: ❌ 禁用 (单文件模式)")
    print()

    # 运行扫描
    try:
        result = asyncio.run(run_security_scan(
            code=code,
            project_name=project_name,
            mode=mode,
            output_dir=args.output,
            verbose=args.verbose,
            project_path=project_path,  # 🔥 传递项目路径，启用本地上下文
        ))

        # 返回状态码
        if result.statistics["confirmed"] > 0:
            # 发现漏洞
            severity = result.statistics["severity_distribution"]
            if severity["critical"] > 0 or severity["high"] > 0:
                return 2  # 高危
            return 1  # 中低危
        return 0  # 无漏洞

    except KeyboardInterrupt:
        print("\n[INFO] 扫描被用户中断")
        return 130
    except Exception as e:
        print(f"[ERROR] 扫描失败: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
