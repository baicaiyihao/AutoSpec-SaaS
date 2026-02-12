"""
AutoSpec Web API 入口

启动命令:
    uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
"""
import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .config import get_settings

# 前端静态文件目录
FRONTEND_DIR = Path(__file__).parent.parent.parent / "frontend" / "dist"
from .routers import projects, audits, reports, review, auth, users, source, rules, tokens
from .routers import settings as settings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时初始化
    settings = get_settings()

    # 确保目录存在
    settings.projects_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)

    # 初始化数据库
    from ..storage.database import init_db, seed_default_admin
    await init_db()
    await seed_default_admin()

    print(f"🚀 {settings.app_name} v{settings.app_version} 启动成功")
    print(f"📁 项目目录: {settings.projects_dir}")
    print(f"📊 报告目录: {settings.reports_dir}")

    yield

    # 关闭时清理
    print("👋 API 服务关闭")


def create_app() -> FastAPI:
    """创建 FastAPI 应用"""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AutoSpec - Sui Move 智能合约安全审计平台 API",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS 中间件
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 注册路由
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(users.router, prefix="/api/v1")
    app.include_router(tokens.router, prefix="/api/v1")
    app.include_router(settings_router.router, prefix="/api/v1")
    app.include_router(projects.router, prefix="/api/v1")
    app.include_router(audits.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(review.router, prefix="/api/v1")
    app.include_router(source.router, prefix="/api/v1")
    app.include_router(rules.router, prefix="/api/v1")

    # 健康检查
    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "version": settings.app_version,
            "service": "autospec-api"
        }

    # 如果前端build存在，serve静态文件
    if FRONTEND_DIR.exists():
        # 静态资源 (js, css, images)
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

        # SPA fallback - 所有非API路由返回index.html
        @app.get("/{full_path:path}")
        async def serve_spa(request: Request, full_path: str):
            # API路由不处理
            if full_path.startswith("api/") or full_path in ["docs", "redoc", "health", "openapi.json"]:
                return {"detail": "Not Found"}

            index_file = FRONTEND_DIR / "index.html"
            if index_file.exists():
                return FileResponse(index_file)
            return {"message": "Frontend not built"}
    else:
        @app.get("/")
        async def root():
            return {
                "message": "Welcome to AutoSpec API",
                "docs": "/docs",
                "health": "/health"
            }

    return app


# 应用实例
app = create_app()
