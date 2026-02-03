#!/bin/bash

# AutoSpec 快速部署脚本
# 适用于 Linux/macOS

set -e  # 遇到错误立即退出

echo "========================================"
echo "🚀 AutoSpec 快速部署脚本"
echo "========================================"

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查 Python
echo -e "\n${GREEN}[1/6]${NC} 检查 Python 环境..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ 未找到 Python 3，请先安装 Python 3.9+${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo -e "✅ Python 版本: $PYTHON_VERSION"

# 检查 Node.js
echo -e "\n${GREEN}[2/6]${NC} 检查 Node.js 环境..."
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ 未找到 Node.js，请先安装 Node.js 18+${NC}"
    exit 1
fi
NODE_VERSION=$(node --version)
echo -e "✅ Node.js 版本: $NODE_VERSION"

# 安装 Python 依赖
echo -e "\n${GREEN}[3/6]${NC} 安装 Python 依赖..."
if [ ! -d "venv" ]; then
    echo "创建虚拟环境..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "✅ Python 依赖安装完成"

# 安装前端依赖
echo -e "\n${GREEN}[4/6]${NC} 安装前端依赖..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
else
    echo "node_modules 已存在，跳过安装"
fi
cd ..
echo -e "✅ 前端依赖安装完成"

# 配置环境变量
echo -e "\n${GREEN}[5/6]${NC} 配置环境变量..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "✅ 已创建 .env 文件（从 .env.example 复制）"
        echo -e "${YELLOW}⚠️  请编辑 .env 文件，配置您的 API Keys${NC}"
    else
        echo -e "${YELLOW}⚠️  未找到 .env.example，将使用默认配置${NC}"
    fi
else
    echo -e "✅ .env 文件已存在"
fi

# 初始化数据库
echo -e "\n${GREEN}[6/7]${NC} 初始化数据库..."
python3 scripts/init_database.py
echo -e "✅ 数据库初始化完成"

# 种子数据（Sui 配置）
echo -e "\n${GREEN}[7/7]${NC} 初始化系统配置..."
python3 scripts/seed_sui_settings.py
echo -e "✅ 系统配置初始化完成"

# 完成
echo -e "\n========================================"
echo -e "${GREEN}✅ 部署完成！${NC}"
echo -e "========================================"
echo ""
echo "📚 下一步："
echo ""
echo "1. 配置 .env 文件中的 API Keys（必需）："
echo "   - DASHSCOPE_API_KEY (必需，用于 LLM 调用)"
echo "   - DEEPSEEK_API_KEY (可选)"
echo "   - ZHIPU_API_KEY (可选)"
echo ""
echo "2. 启动后端服务："
echo "   python3 scripts/start_backend.py"
echo ""
echo "3. 启动前端开发服务器（另开一个终端）："
echo "   cd frontend && npm run dev"
echo ""
echo "4. 访问 Web UI："
echo "   C端用户: http://localhost:5173 (钱包登录)"
echo "   管理后台: http://localhost:5173/admin-login (密码登录)"
echo ""
echo "5. 默认管理员账号："
echo "   用户名: admin"
echo "   密码: admin123"
echo "   (首次登录后请立即修改密码)"
echo ""
echo "6. 配置 Sui 合约（可选，仅使用 Token 充值功能时需要）："
echo "   登录管理后台 -> 系统设置 -> 填写合约 Package ID 和 Pool ID"
echo ""
echo "========================================"
echo -e "${YELLOW}💡 提示${NC}"
echo "========================================"
echo "• 基础审计功能需要 DASHSCOPE_API_KEY"
echo "• 用户可使用自己的 API Key (own_key 模式)"
echo "• 或购买平台 Token (platform_token 模式)"
echo "• Token 充值需要配置 Sui 智能合约"
echo "========================================"
