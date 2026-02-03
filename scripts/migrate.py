#!/usr/bin/env python3
"""
数据库迁移脚本

Usage:
    python scripts/migrate.py          # 升级到最新版本
    python scripts/migrate.py upgrade  # 升级到最新版本
    python scripts/migrate.py downgrade # 回退一个版本
    python scripts/migrate.py history  # 查看迁移历史
"""
import subprocess
import sys
from pathlib import Path

# 确保在项目根目录执行
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def run_alembic(args: list[str]):
    """运行 alembic 命令"""
    cmd = ["alembic"] + args
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=project_root)
    return result.returncode


def main():
    if len(sys.argv) == 1:
        # 默认升级到最新版本
        return run_alembic(["upgrade", "head"])

    command = sys.argv[1]

    if command == "upgrade":
        return run_alembic(["upgrade", "head"])
    elif command == "downgrade":
        return run_alembic(["downgrade", "-1"])
    elif command == "history":
        return run_alembic(["history"])
    elif command == "current":
        return run_alembic(["current"])
    elif command == "revision":
        # 创建新的迁移
        message = input("Enter migration message: ")
        return run_alembic(["revision", "--autogenerate", "-m", message])
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
