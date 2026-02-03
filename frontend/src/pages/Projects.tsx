import { useEffect, useState, useRef } from 'react'
import { Card, Table, Button, Modal, Form, Input, message, Popconfirm, Space, Tag, Tabs, Progress, Select } from 'antd'
import {
  PlusOutlined,
  DeleteOutlined,
  PlayCircleOutlined,
  FolderOpenOutlined,
  UploadOutlined,
  InboxOutlined,
  LoadingOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  EyeOutlined,
  ReloadOutlined,
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { projectApi, auditApi } from '../services/api'
import type { Project } from '../types'
import { formatDateTime } from '../utils/time'

export default function Projects() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [projects, setProjects] = useState<Project[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [modalVisible, setModalVisible] = useState(false)
  const [createMode, setCreateMode] = useState<'upload' | 'path'>('upload')
  const [uploadFiles, setUploadFiles] = useState<File[]>([])
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const [isDragging, setIsDragging] = useState(false)
  const folderInputRef = useRef<HTMLInputElement>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    loadProjects()
  }, [page, pageSize])

  const loadProjects = async () => {
    try {
      setLoading(true)
      const res = await projectApi.list({
        skip: (page - 1) * pageSize,
        limit: pageSize,
      })
      setProjects(res.items)
      setTotal(res.total)
    } catch (error) {
      message.error('加载项目列表失败')
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = async (values: { name: string; description?: string; source_path?: string; blockchain?: string }) => {
    if (createMode === 'upload') {
      await handleUpload(values)
    } else {
      try {
        if (!values.source_path) {
          message.error('请输入源码路径')
          return
        }
        await projectApi.create({
          name: values.name,
          description: values.description,
          source_path: values.source_path,
          blockchain: values.blockchain,
        })
        message.success('项目创建成功')
        setModalVisible(false)
        form.resetFields()
        loadProjects()
      } catch (error: any) {
        message.error(error.response?.data?.detail || '项目创建失败')
      }
    }
  }

  const getFilteredUploadFiles = () => {
    if (uploadFiles.length === 0) return { moveFiles: [], tomlFiles: [] }

    const firstPath = (uploadFiles[0] as any).webkitRelativePath || ''
    const folderName = firstPath.split('/')[0]

    // sources/ 下的 .move 文件
    const moveFiles = uploadFiles.filter((f) => {
      const relPath = (f as any).webkitRelativePath || f.name
      const parts = relPath.split('/')
      if (parts.length <= 1) return false
      const withoutRoot = parts.slice(1).join('/')
      return withoutRoot.startsWith('sources/') && f.name.endsWith('.move')
    })

    // 根目录 Move.toml
    const tomlFiles = uploadFiles.filter((f) => {
      const relPath = (f as any).webkitRelativePath || f.name
      const parts = relPath.split('/')
      return parts.length === 2 && parts[0] === folderName && f.name === 'Move.toml'
    })

    return { moveFiles, tomlFiles }
  }

  const handleUpload = async (values: { name: string; description?: string; blockchain?: string }) => {
    if (uploadFiles.length === 0) {
      message.error('请选择要上传的文件夹')
      return
    }

    const { moveFiles, tomlFiles } = getFilteredUploadFiles()
    if (moveFiles.length === 0) {
      message.error('未找到 sources/ 目录下的 .move 文件，请确保选择的是 Move 项目文件夹')
      return
    }

    try {
      setUploading(true)
      setUploadProgress(0)

      const formData = new FormData()
      formData.append('name', values.name)
      if (values.description) {
        formData.append('description', values.description)
      }
      if (values.blockchain) {
        formData.append('blockchain', values.blockchain)
      }

      // 添加过滤后的文件，保留相对路径
      const allFiles = [...moveFiles, ...tomlFiles]
      allFiles.forEach((file) => {
        const relativePath = (file as any).webkitRelativePath || file.name
        formData.append('files', file, relativePath)
      })

      await projectApi.upload(formData, (progress) => {
        setUploadProgress(Math.round(progress * 100))
      })

      message.success(`项目创建成功，已上传 ${moveFiles.length} 个 .move 文件`)
      setModalVisible(false)
      form.resetFields()
      setUploadFiles([])
      setUploadProgress(0)
      loadProjects()
    } catch (error: any) {
      message.error(error.response?.data?.detail || '上传失败')
    } finally {
      setUploading(false)
    }
  }

  const handleFolderSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    processFiles(files)
  }

  // 处理文件列表（拖拽或选择）
  const processFiles = (files: File[]) => {
    setUploadFiles(files)

    // 自动填充项目名称（使用文件夹名）
    if (files.length > 0) {
      const firstPath = (files[0] as any).webkitRelativePath || ''
      const folderName = firstPath.split('/')[0]
      if (folderName && !form.getFieldValue('name')) {
        form.setFieldValue('name', folderName)
      }
    }
  }

  // 递归读取拖拽的文件夹
  const readDirectory = async (entry: FileSystemDirectoryEntry, path: string = ''): Promise<File[]> => {
    const files: File[] = []
    const reader = entry.createReader()

    const readEntries = (): Promise<FileSystemEntry[]> => {
      return new Promise((resolve, reject) => {
        reader.readEntries(resolve, reject)
      })
    }

    let entries: FileSystemEntry[] = []
    let batch: FileSystemEntry[]
    do {
      batch = await readEntries()
      entries = entries.concat(batch)
    } while (batch.length > 0)

    for (const childEntry of entries) {
      const childPath = path ? `${path}/${childEntry.name}` : childEntry.name
      if (childEntry.isFile) {
        const fileEntry = childEntry as FileSystemFileEntry
        const file = await new Promise<File>((resolve, reject) => {
          fileEntry.file((f) => {
            // 给文件添加相对路径
            Object.defineProperty(f, 'webkitRelativePath', {
              value: childPath,
              writable: false
            })
            resolve(f)
          }, reject)
        })
        files.push(file)
      } else if (childEntry.isDirectory) {
        const subFiles = await readDirectory(childEntry as FileSystemDirectoryEntry, childPath)
        files.push(...subFiles)
      }
    }
    return files
  }

  // 拖拽处理
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    const items = e.dataTransfer.items
    if (!items || items.length === 0) return

    // 获取第一个拖入的项目
    const item = items[0]
    const entry = item.webkitGetAsEntry()

    if (!entry) {
      message.error('无法读取拖入的内容')
      return
    }

    if (!entry.isDirectory) {
      message.error('请拖入文件夹，不是单个文件')
      return
    }

    try {
      message.loading({ content: '正在读取文件夹...', key: 'reading' })
      const files = await readDirectory(entry as FileSystemDirectoryEntry, entry.name)
      message.destroy('reading')

      if (files.length === 0) {
        message.error('文件夹为空')
        return
      }

      processFiles(files)
      message.success(`已读取 ${files.length} 个文件`)
    } catch (error) {
      message.destroy('reading')
      message.error('读取文件夹失败')
      console.error(error)
    }
  }

  const handleBatchDelete = async () => {
    try {
      await Promise.all(selectedRowKeys.map((id) => projectApi.delete(id)))
      message.success(`已删除 ${selectedRowKeys.length} 个项目`)
      setSelectedRowKeys([])
      loadProjects()
    } catch (error) {
      message.error('删除失败')
    }
  }

  const handleStartAudit = async (project: Project) => {
    try {
      const audit = await auditApi.create({ project_id: project.id })
      // 如果返回的审计状态是 running 或 pending，说明是已存在的任务
      if (audit.status === 'running' || audit.status === 'pending') {
        message.info('已有运行中的审计任务，正在跳转...')
      } else {
        message.success('审计任务已创建')
      }
      navigate(`/audits/${audit.id}`)
    } catch (error) {
      message.error('创建审计任务失败')
    }
  }

  // 获取项目的审计状态按钮
  const renderAuditButton = (project: Project) => {
    const status = project.last_audit_status

    if (status === 'running' || status === 'pending') {
      return (
        <Button
          type="primary"
          size="small"
          icon={<LoadingOutlined spin />}
          onClick={() => navigate(`/audits/${project.last_audit_id}`)}
        >
          查看进度
        </Button>
      )
    }

    if (status === 'completed' && project.last_audit_id) {
      return (
        <Space>
          <Button
            size="small"
            icon={<EyeOutlined />}
            onClick={() => navigate(`/audits/${project.last_audit_id}`)}
          >
            审计详情
          </Button>
          <Button
            type="primary"
            size="small"
            icon={<PlayCircleOutlined />}
            onClick={() => handleStartAudit(project)}
          >
            重新审计
          </Button>
        </Space>
      )
    }

    return (
      <Button
        type="primary"
        size="small"
        icon={<PlayCircleOutlined />}
        onClick={() => handleStartAudit(project)}
      >
        开始审计
      </Button>
    )
  }

  const columns = [
    {
      title: '项目名称',
      dataIndex: 'name',
      key: 'name',
      render: (name: string, record: Project) => (
        <Button type="link" onClick={() => navigate(`/projects/${record.id}`)}>
          <FolderOpenOutlined className="mr-1" />
          {name}
        </Button>
      ),
    },
    {
      title: '链',
      dataIndex: 'blockchain',
      key: 'blockchain',
      width: 100,
      render: (blockchain?: string) =>
        blockchain ? <Tag color="blue">{blockchain.toUpperCase()}</Tag> : <Tag>未选择</Tag>,
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (desc?: string) => desc || <span className="text-gray-400">-</span>,
    },
    {
      title: '文件数',
      dataIndex: 'file_count',
      key: 'file_count',
      width: 100,
      render: (count: number) => <Tag>{count} 文件</Tag>,
    },
    {
      title: '路径',
      dataIndex: 'source_path',
      key: 'source_path',
      ellipsis: true,
      render: (path: string) => (
        <code className="text-xs bg-gray-100 px-2 py-1 rounded">{path}</code>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (date: string) => formatDateTime(date),
    },
    {
      title: '最新审计',
      key: 'last_audit',
      width: 120,
      render: (_: unknown, record: Project) => {
        const status = record.last_audit_status
        if (!status) return <span className="text-gray-400">未审计</span>
        const configs: Record<string, { color: string; text: string; icon: React.ReactNode }> = {
          pending: { color: 'default', text: '等待中', icon: <LoadingOutlined /> },
          running: { color: 'processing', text: '运行中', icon: <LoadingOutlined spin /> },
          completed: { color: 'success', text: '已完成', icon: <CheckCircleOutlined /> },
          failed: { color: 'error', text: '失败', icon: <CloseCircleOutlined /> },
          cancelled: { color: 'warning', text: '已取消', icon: null },
        }
        const cfg = configs[status] || { color: 'default', text: status, icon: null }
        return <Tag color={cfg.color} icon={cfg.icon}>{cfg.text}</Tag>
      },
    },
    {
      title: '操作',
      key: 'action',
      width: 220,
      render: (_: unknown, record: Project) => renderAuditButton(record),
    },
  ]

  return (
    <div>
      <Card
        title="项目管理"
        extra={
          <Space>
            <Popconfirm
              title="确认删除"
              description={`确认删除选中的 ${selectedRowKeys.length} 个项目？相关审计记录也将被删除。`}
              onConfirm={handleBatchDelete}
              okText="删除"
              cancelText="取消"
              okButtonProps={{ danger: true }}
              disabled={selectedRowKeys.length === 0}
            >
              <Button
                danger
                icon={<DeleteOutlined />}
                disabled={selectedRowKeys.length === 0}
              >
                删除{selectedRowKeys.length > 0 ? ` (${selectedRowKeys.length})` : ''}
              </Button>
            </Popconfirm>
            <Button icon={<ReloadOutlined />} onClick={() => loadProjects()}>
              刷新
            </Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalVisible(true)}>
              添加项目
            </Button>
          </Space>
        }
      >
        <Table
          loading={loading}
          dataSource={projects}
          columns={columns}
          rowKey="id"
          rowSelection={{
            selectedRowKeys,
            onChange: (keys) => setSelectedRowKeys(keys as string[]),
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 个项目`,
            onChange: (p, ps) => {
              setPage(p)
              setPageSize(ps)
            },
          }}
        />
      </Card>

      <Modal
        title="添加项目"
        open={modalVisible}
        width={600}
        onCancel={() => {
          setModalVisible(false)
          form.resetFields()
          setUploadFiles([])
          setUploadProgress(0)
        }}
        onOk={() => form.submit()}
        okText={uploading ? '上传中...' : '创建'}
        okButtonProps={{ loading: uploading }}
        cancelText="取消"
      >
        <Tabs
          activeKey={createMode}
          onChange={(key) => setCreateMode(key as 'upload' | 'path')}
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

        <Form form={form} layout="vertical" onFinish={handleCreate} className="mt-4">
          <Form.Item
            name="name"
            label="项目名称"
            rules={[{ required: true, message: '请输入项目名称' }]}
          >
            <Input placeholder="例如：my-defi-protocol" />
          </Form.Item>
          <Form.Item name="description" label="项目描述">
            <Input.TextArea rows={2} placeholder="简要描述项目功能" />
          </Form.Item>

          <Form.Item
            name="blockchain"
            label="所属链"
            tooltip="选择项目所属的区块链，审计时将自动使用该链的规则"
          >
            <Select placeholder="选择区块链" allowClear>
              <Select.Option value="sui">Sui Move</Select.Option>
            </Select>
          </Form.Item>

          {createMode === 'upload' ? (
            <Form.Item label="选择文件夹" required>
              {/* 隐藏的文件夹选择器（备选方案） */}
              <input
                ref={folderInputRef}
                type="file"
                // @ts-ignore - webkitdirectory is not in standard types
                webkitdirectory=""
                directory=""
                multiple
                style={{ display: 'none' }}
                onChange={handleFolderSelect}
              />

              <div
                className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors ${
                  isDragging
                    ? 'border-blue-500 bg-blue-50'
                    : uploadFiles.length > 0
                    ? 'border-green-400 bg-green-50'
                    : 'border-gray-300 hover:border-blue-400'
                }`}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => folderInputRef.current?.click()}
              >
                {isDragging ? (
                  <div>
                    <InboxOutlined className="text-4xl text-blue-500 mb-2" />
                    <div className="text-blue-500 font-medium">释放鼠标上传文件夹</div>
                  </div>
                ) : uploadFiles.length > 0 ? (
                  <div>
                    <FolderOpenOutlined className="text-4xl text-green-500 mb-2" />
                    <div className="text-gray-600">
                      已识别 <strong className="text-green-600">{getFilteredUploadFiles().moveFiles.length}</strong> 个 sources/ 下的 .move 文件
                    </div>
                    <div className="text-gray-400 text-sm mt-1">
                      共 {uploadFiles.length} 个文件，拖入新文件夹或点击重新选择
                    </div>
                  </div>
                ) : (
                  <div>
                    <InboxOutlined className="text-4xl text-gray-400 mb-2" />
                    <div className="text-gray-600 font-medium">拖拽 Move 项目文件夹到此处</div>
                    <div className="text-gray-400 text-sm mt-1">
                      将提取 sources/ 下的 .move 文件和 Move.toml
                    </div>
                    <div className="text-gray-400 text-xs mt-2">
                      或 <span className="text-blue-500 underline">点击选择</span>（会有浏览器确认提示）
                    </div>
                  </div>
                )}
              </div>

              {uploading && (
                <Progress percent={uploadProgress} size="small" className="mt-2" />
              )}
            </Form.Item>
          ) : (
            <Form.Item
              name="source_path"
              label="源码路径"
              rules={[{ required: createMode === 'path', message: '请输入源码路径' }]}
              extra="服务器本地路径，适合后端和项目在同一机器的情况"
            >
              <Input placeholder="/path/to/move-project" />
            </Form.Item>
          )}
        </Form>
      </Modal>
    </div>
  )
}
