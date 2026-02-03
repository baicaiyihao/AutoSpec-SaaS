#!/usr/bin/env python3
"""
后端启动脚本 - 自动处理数据库迁移
"""
import os
import sys
import subprocess
from pathlib import Path

# 添加项目根目录到 Python 路径
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))


def run_command(cmd: list[str], description: str):
    """执行命令并显示友好的输出"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, cwd=BASE_DIR, check=True, capture_output=True, text=True)
        print(f"✅ {description} 完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} 失败:")
        print(e.stderr)
        return False


def main():
    print("=" * 60)
    print("🚀 AutoSpec Backend 启动脚本")
    print("=" * 60)

    # 1. 检查环境变量
    print("\n📋 检查环境配置...")
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        print("⚠️  未找到 .env 文件，将使用默认配置")
        print("💡 提示: 复制 .env.example 为 .env 并配置 API Keys")

    # 检查必要的 API Key
    dashscope_key = os.getenv("DASHSCOPE_API_KEY")
    if not dashscope_key:
        print("⚠️  未设置 DASHSCOPE_API_KEY (核心功能需要)")
    else:
        print(f"✅ DASHSCOPE_API_KEY: {dashscope_key[:10]}...")

    # 2. 自动运行数据库迁移
    print("\n📦 初始化数据库...")
    if not run_command([sys.executable, "-m", "scripts.migrate"], "数据库迁移"):
        print("⚠️  数据库迁移失败，但仍将尝试启动后端")

    # 3. 启动后端服务
    print("\n🌐 启动后端服务...")
    print("=" * 60)
    print("📍 API 地址: http://localhost:8000")
    print("📍 API 文档: http://localhost:8000/docs")
    print("📍 管理员账号: admin / admin123")
    print("=" * 60)
    print("\n按 Ctrl+C 停止服务\n")

    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "src.api.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload"
        ], cwd=BASE_DIR)
    except KeyboardInterrupt:
        print("\n\n👋 后端服务已停止")


if __name__ == "__main__":
    main()
