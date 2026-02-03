/**
 * 全局错误边界组件
 */
import React, { Component, ReactNode } from 'react'
import { Result, Button } from 'antd'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
    window.location.href = '/'
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100">
          <Result
            status="error"
            title="页面出错了"
            subTitle={
              <div>
                <p>抱歉，页面遇到了一个错误。请尝试刷新页面或返回首页。</p>
                {this.state.error && (
                  <details className="mt-4 text-left">
                    <summary className="cursor-pointer text-gray-600">查看错误详情</summary>
                    <pre className="mt-2 p-4 bg-gray-50 rounded text-xs overflow-auto">
                      {this.state.error.toString()}
                      {'\n'}
                      {this.state.error.stack}
                    </pre>
                  </details>
                )}
              </div>
            }
            extra={[
              <Button type="primary" key="home" onClick={this.handleReset}>
                返回首页
              </Button>,
              <Button key="reload" onClick={() => window.location.reload()}>
                刷新页面
              </Button>,
            ]}
          />
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
