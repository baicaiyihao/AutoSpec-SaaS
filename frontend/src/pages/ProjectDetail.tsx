import { useEffect, useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Card, Descriptions, Button, Table, Spin, message, Empty, Space, Modal, Tabs, Input, Progress } from 'antd'
import {
  ArrowLeftOutlined,
  PlayCircleOutlined,
  FileOutlined,
  UploadOutlined,
  FolderOpenOutlined,
  InboxOutlined,
} from '@ant-design/icons'
import { projectApi, auditApi } from '../services/api'
import type { Project } from '../types'
import { formatDateTime } from '../utils/time'

interface FileItem {
  path: string
  name: string
  size: number
}

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [project, setProject] = useState<Project | null>(null)
  const [files, setFiles] = useState<FileItem[]>([])
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [fileContent, setFileContent] = useState<string>('')
  const [contentLoading, setContentLoading] = useState(false)

  // 重新导入相关
  const [reimportVisible, setReimportVisible] = useState(false)
  const [reimportMode, setReimportMode] = useState<'upload' | 'path'>('upload')
  const [reimportFiles, setReimportFiles] = useState<File[]>([])
  const [reimportPath, setReimportPath] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const folderInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (id) {
      loadProject()
    }
  }, [id])

  const loadProject = async () => {
    try {
      setLoading(true)
      const [projectData, filesData] = await Promise.all([
        projectApi.get(id!),
        projectApi.getFiles(id!),
      ])
      setProject(projectData)
      setFiles(filesData)
    } catch (error) {
      message.error('加载项目详情失败')
    } finally {
      setLoading(false)
    }
  }

  const loadFileContent = async (filePath: string) => {
    try {
      setContentLoading(true)
      setSelectedFile(filePath)
      const content = await projectApi.getFileContent(id!, filePath)
      setFileContent(content)
    } catch (error) {
      message.error('加载文件内容失败')
    } finally {
      setContentLoading(false)
    }
  }

  const handleStartAudit = async () => {
    if (!project) return
    try {
      const audit = await auditApi.create({ project_id: project.id })
      if (audit.status === 'running' || audit.status === 'pending') {
        message.info('已有运行中的审计任务，正在跳转...')
      } else {
        message.success('审计任务已创建')
      }
      navigate(`/audits/${audit.id}`)
    } catch (error: any) {
      const detail = error.response?.data?.detail || error.message || '未知错误'

      // 🔥 Token 额度不足特殊提示
      if (error.response?.status === 403 && detail.includes('Token')) {
        message.error({
          content: detail + ' - 请前往用户设置查看额度',
          duration: 10,
        })
      } else {
        message.error(`创建审计任务失败: ${detail}`)
      }
    }
  }

  const handleFolderSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    setReimportFiles(files)
  }

  const getFilteredFiles = () => {
    if (reimportFiles.length === 0) return { moveFiles: [], tomlFiles: [] }

    const firstPath = (reimportFiles[0] as any).webkitRelativePath || ''
    const folderName = firstPath.split('/')[0]

    const moveFiles = reimportFiles.filter((f) => {
      const relPath = (f as any).webkitRelativePath || f.name
      // 移除顶层文件夹名后，检查是否在 sources/ 下
      const parts = relPath.split('/')
      if (parts.length <= 1) return false
      const withoutRoot = parts.slice(1).join('/')
      return withoutRoot.startsWith('sources/') && f.name.endsWith('.move')
    })

    const tomlFiles = reimportFiles.filter((f) => {
      const relPath = (f as any).webkitRelativePath || f.name
      const parts = relPath.split('/')
      // 根目录 Move.toml: folderName/Move.toml
      return parts.length === 2 && parts[0] === folderName && f.name === 'Move.toml'
    })

    return { moveFiles, tomlFiles }
  }

  const handleReimport = async () => {
    if (reimportMode === 'upload') {
      const { moveFiles, tomlFiles } = getFilteredFiles()
      if (moveFiles.length === 0) {
        message.error('未找到 sources/ 目录下的 .move 文件')
        return
      }

      try {
        setUploading(true)
        setUploadProgress(0)

        const formData = new FormData()
        const allFiles = [...moveFiles, ...tomlFiles]
        allFiles.forEach((file) => {
          const relativePath = (file as any).webkitRelativePath || file.name
          formData.append('files', file, relativePath)
        })

        await projectApi.reimport(id!, formData, (progress) => {
          setUploadProgress(Math.round(progress * 100))
        })

        message.success(`重新导入成功，已上传 ${moveFiles.length} 个 .move 文件`)
        setReimportVisible(false)
        setReimportFiles([])
        setUploadProgress(0)
        setSelectedFile(null)
        setFileContent('')
        loadProject()
      } catch (error: any) {
        message.error(error.response?.data?.detail || '重新导入失败')
      } finally {
        setUploading(false)
      }
    } else {
      if (!reimportPath.trim()) {
        message.error('请输入源码路径')
        return
      }

      try {
        setUploading(true)
        await projectApi.reimportPath(id!, reimportPath.trim())
        message.success('重新导入成功')
        setReimportVisible(false)
        setReimportPath('')
        setSelectedFile(null)
        setFileContent('')
        loadProject()
      } catch (error: any) {
        message.error(error.response?.data?.detail || '重新导入失败')
      } finally {
        setUploading(false)
      }
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spin size="large" />
      </div>
    )
  }

  if (!project) {
    return <Empty description="项目不存在" />
  }

  const { moveFiles } = reimportFiles.length > 0 ? getFilteredFiles() : { moveFiles: [] }

  const fileColumns = [
    {
      title: '文件',
      dataIndex: 'name',
      key: 'name',
      render: (_: string, record: FileItem) => (
        <Button
          type="link"
          icon={<FileOutlined />}
          onClick={() => loadFileContent(record.path)}
          className={selectedFile === record.path ? 'text-blue-600 font-medium' : ''}
        >
          {record.path}
        </Button>
      ),
    },
    {
      title: '大小',
      dataIndex: 'size',
      key: 'size',
      width: 100,
      render: (size: number) => `${(size / 1024).toFixed(1)} KB`,
    },
  ]

  return (
    <div className="space-y-4">
      {/* 头部 */}
      <div className="flex items-center justify-between">
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/projects')}>
          返回项目列表
        </Button>
        <Space>
          <Button icon={<UploadOutlined />} onClick={() => setReimportVisible(true)}>
            重新导入
          </Button>
          <Button type="primary" icon={<PlayCircleOutlined />} onClick={handleStartAudit}>
            开始审计
          </Button>
        </Space>
      </div>

      {/* 项目信息 */}
      <Card title="项目信息">
        <Descriptions column={2}>
          <Descriptions.Item label="项目名称">{project.name}</Descriptions.Item>
          <Descriptions.Item label="文件数量">{project.file_count} 个文件</Descriptions.Item>
          <Descriptions.Item label="源码路径" span={2}>
            <code className="bg-gray-100 px-2 py-1 rounded">{project.source_path}</code>
          </Descriptions.Item>
          <Descriptions.Item label="描述" span={2}>
            {project.description || '-'}
          </Descriptions.Item>
          <Descriptions.Item label="创建时间">
            {formatDateTime(project.created_at)}
          </Descriptions.Item>
          <Descriptions.Item label="更新时间">
            {formatDateTime(project.updated_at)}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      {/* 文件列表和内容 */}
      <div className="grid grid-cols-3 gap-4">
        <Card title="文件列表" className="col-span-1">
          <Table
            dataSource={files}
            columns={fileColumns}
            rowKey="path"
            size="small"
            pagination={false}
            scroll={{ y: 400 }}
          />
        </Card>
        <Card
          title={selectedFile ? `文件内容: ${selectedFile}` : '请选择文件'}
          className="col-span-2"
        >
          {contentLoading ? (
            <div className="flex items-center justify-center h-64">
              <Spin />
            </div>
          ) : fileContent ? (
            <pre className="code-block max-h-[500px] overflow-auto">
              {fileContent}
            </pre>
          ) : (
            <Empty description="点击左侧文件查看内容" />
          )}
        </Card>
      </div>

      {/* 重新导入 Modal */}
      <Modal
        title="重新导入项目"
        open={reimportVisible}
        width={600}
        onCancel={() => {
          setReimportVisible(false)
          setReimportFiles([])
          setReimportPath('')
          setUploadProgress(0)
        }}
        onOk={handleReimport}
        okText={uploading ? '导入中...' : '确认导入'}
        okButtonProps={{ loading: uploading }}
        cancelText="取消"
      >
        <Tabs
          activeKey={reimportMode}
          onChange={(key) => setReimportMode(key as 'upload' | 'path')}
          items={[
            {
              key: 'upload',
              label: (
                <span>
                  <UploadOutlined /> 上传文件夹
                </span>
              ),
            },
            {
              key: 'path',
              label: (
                <span>
                  <FolderOpenOutlined /> 本地路径
                </span>
              ),
            },
          ]}
        />

        {reimportMode === 'upload' ? (
          <div className="mt-4">
            {/* 隐藏的文件夹选择器 */}
            <input
              ref={folderInputRef}
              type="file"
              // @ts-ignore
              webkitdirectory=""
              directory=""
              multiple
              style={{ display: 'none' }}
              onChange={handleFolderSelect}
            />

            <div
              className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center cursor-pointer hover:border-blue-400 transition-colors"
              onClick={() => folderInputRef.current?.click()}
            >
              {reimportFiles.length > 0 ? (
                <div>
                  <FolderOpenOutlined className="text-4xl text-blue-500 mb-2" />
                  <div className="text-gray-600">
                    已识别 <strong>{moveFiles.length}</strong> 个 sources/ 下的 .move 文件
                  </div>
                  <div className="text-gray-400 text-sm mt-1">
                    共 {reimportFiles.length} 个文件，点击重新选择
                  </div>
                </div>
              ) : (
                <div>
                  <InboxOutlined className="text-4xl text-gray-400 mb-2" />
                  <div className="text-gray-500">点击选择 Move 项目文件夹</div>
                  <div className="text-gray-400 text-sm mt-1">
                    将提取 sources/ 下的 .move 文件和 Move.toml
                  </div>
                </div>
              )}
            </div>

            {uploading && (
              <Progress percent={uploadProgress} size="small" className="mt-2" />
            )}

            <div className="mt-3 text-gray-400 text-xs">
              注意：重新导入将替换项目中的所有现有文件
            </div>
          </div>
        ) : (
          <div className="mt-4">
            <Input
              value={reimportPath}
              onChange={(e) => setReimportPath(e.target.value)}
              placeholder="/path/to/move-project"
            />
            <div className="mt-2 text-gray-400 text-xs">
              服务器本地路径，将更新项目的源码路径指向
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
