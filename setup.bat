@echo off
chcp 65001 >nul
REM AutoSpec 快速部署脚本 (Windows)

echo ========================================
echo 🚀 AutoSpec 快速部署脚本
echo ========================================

REM 检查 Python
echo.
echo [1/6] 检查 Python 环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 未找到 Python，请先安装 Python 3.9+
    pause
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo ✅ Python 版本: %PYTHON_VERSION%

REM 检查 Node.js
echo.
echo [2/6] 检查 Node.js 环境...
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 未找到 Node.js，请先安装 Node.js 18+
    pause
    exit /b 1
)
for /f %%i in ('node --version') do set NODE_VERSION=%%i
echo ✅ Node.js 版本: %NODE_VERSION%

REM 安装 Python 依赖
echo.
echo [3/6] 安装 Python 依赖...
if not exist "venv" (
    echo 创建虚拟环境...
    python -m venv venv
)
call venv\Scripts\activate.bat
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
echo ✅ Python 依赖安装完成

REM 安装前端依赖
echo.
echo [4/6] 安装前端依赖...
cd frontend
if not exist "node_modules" (
    call npm install
) else (
    echo node_modules 已存在，跳过安装
)
cd ..
echo ✅ 前端依赖安装完成

REM 配置环境变量
echo.
echo [5/6] 配置环境变量...
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo ✅ 已创建 .env 文件（从 .env.example 复制）
        echo ⚠️  请编辑 .env 文件，配置您的 API Keys
    ) else (
        echo ⚠️  未找到 .env.example，将使用默认配置
    )
) else (
    echo ✅ .env 文件已存在
)

REM 初始化数据库
echo.
echo [6/6] 初始化数据库...
python scripts\migrate.py
echo ✅ 数据库初始化完成

REM 完成
echo.
echo ========================================
echo ✅ 部署完成！
echo ========================================
echo.
echo 📚 下一步：
echo.
echo 1. 启动后端服务：
echo    python scripts\start_backend.py
echo.
echo 2. 启动前端开发服务器（另开一个终端）：
echo    cd frontend ^&^& npm run dev
echo.
echo 3. 访问 Web UI:
echo    http://localhost:5173
echo.
echo 4. 默认管理员账号:
echo    用户名: admin
echo    密码: admin123
echo    (首次登录需强制修改密码)
echo.
echo ========================================
echo 💡 提示: 确保已配置 .env 文件中的 API Keys
echo ========================================
echo.
pause
