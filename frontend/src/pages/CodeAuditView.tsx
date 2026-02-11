/**
 * 代码审计视图
 *
 * 类似 SonarQube 的代码审计界面：
 * - 左侧：文件树 + 漏洞列表
 * - 右侧：Monaco Editor 代码查看器
 * - 支持点击漏洞跳转到对应代码位置
 */
import { useEffect, useState, useRef, useCallback } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import {
  Layout,
  Tree,
  Tag,
  Spin,
  Empty,
  Button,
  Tabs,
  Badge,
  message,
  Collapse,
  Input,
  Select,
  Popover,
  Radio,
  Modal,
} from 'antd'
import {
  ArrowLeftOutlined,
  FileOutlined,
  FolderOutlined,
  BugOutlined,
  CodeOutlined,
  CommentOutlined,
  SendOutlined,
  TagOutlined,
  PlusOutlined,
  UpOutlined,
  DownOutlined,
} from '@ant-design/icons'
import Editor, { Monaco } from '@monaco-editor/react'
import type { editor, Position } from 'monaco-editor'
import { projectApi, reportApi, reviewApi, auditApi } from '../services/api'
import type { Finding, Severity, ReviewSession } from '../types'
import { formatDateTime } from '../utils/time'

const { TextArea } = Input

const { Sider, Content } = Layout

// 严重性配置
const SEVERITY_CONFIG: Record<Severity, { color: string; label: string; order: number }> = {
  CRITICAL: { color: '#ff4d4f', label: '危急', order: 0 },
  HIGH: { color: '#ff7a45', label: '高危', order: 1 },
  MEDIUM: { color: '#ffc53d', label: '中危', order: 2 },
  LOW: { color: '#73d13d', label: '低危', order: 3 },
  ADVISORY: { color: '#1890ff', label: '建议', order: 4 },
}

interface FileNode {
  key: string
  title: string
  isLeaf?: boolean
  children?: FileNode[]
  icon?: React.ReactNode
}

interface OpenFile {
  path: string
  name: string
  content: string
}

type FindingMarkType = 'issue' | 'not_issue' | 'legacy'

interface FindingMark {
  type: FindingMarkType
  severity?: 'high' | 'medium'
  note: string
}

const MARK_CONFIG: Record<FindingMarkType, { label: string; color: string }> = {
  issue: { label: '是问题', color: '#ff4d4f' },
  not_issue: { label: '不是问题', color: '#52c41a' },
  legacy: { label: '遗留问题', color: '#faad14' },
}

// 将文件列表转换为树形结构
function buildFileTree(files: Array<{ path: string; name: string }>): FileNode[] {
  const root: FileNode[] = []
  const map = new Map<string, FileNode>()

  // 排序：目录优先，然后按名称
  const sortedFiles = [...files].sort((a, b) => {
    const aDepth = a.path.split('/').length
    const bDepth = b.path.split('/').length
    if (aDepth !== bDepth) return aDepth - bDepth
    return a.path.localeCompare(b.path)
  })

  for (const file of sortedFiles) {
    const parts = file.path.split('/')
    let currentPath = ''

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]
      const isLast = i === parts.length - 1
      const parentPath = currentPath
      currentPath = currentPath ? `${currentPath}/${part}` : part

      if (!map.has(currentPath)) {
        const node: FileNode = {
          key: currentPath,
          title: part,
          isLeaf: isLast,
          icon: isLast ? <FileOutlined /> : <FolderOutlined />,
          children: isLast ? undefined : [],
        }
        map.set(currentPath, node)

        if (parentPath) {
          const parent = map.get(parentPath)
          if (parent && parent.children) {
            parent.children.push(node)
          }
        } else {
          root.push(node)
        }
      }
    }
  }

  return root
}

// 解析漏洞位置（module::function 格式）
function parseLocation(location?: { file: string }): { module: string; func: string; candidates: string[] } | null {
  if (!location?.file) return null
  const parts = location.file.split('::')
  // candidates: all parts that could be a file name match
  const candidates = parts.filter(Boolean)
  if (parts.length >= 3) {
    // e.g. "address::module_name::function" → module=module_name, func=function
    return { module: parts[1], func: parts[2], candidates }
  }
  if (parts.length >= 2) {
    return { module: parts[0], func: parts[1], candidates }
  }
  return { module: parts[0], func: '', candidates }
}

// 在代码中查找函数位置
function findFunctionInCode(code: string, funcName: string): number {
  const lines = code.split('\n')
  for (let i = 0; i < lines.length; i++) {
    // 匹配函数定义：public fun xxx, fun xxx, entry fun xxx 等
    const funcPattern = new RegExp(`\\b(public\\s+)?(entry\\s+)?fun\\s+${funcName}\\s*[<(]`)
    if (funcPattern.test(lines[i])) {
      return i + 1 // 返回行号（1-based）
    }
  }
  return 1
}

interface CodeAuditViewProps {
  reportId?: string
  embedded?: boolean
}

export default function CodeAuditView(props: CodeAuditViewProps) {
  const params = useParams<{ reportId: string }>()
  const reportId = props.reportId || params.reportId
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [loading, setLoading] = useState(true)
  const [projectId, setProjectId] = useState<string>('')
  const [projectName, setProjectName] = useState<string>('')
  const [files, setFiles] = useState<Array<{ path: string; name: string }>>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [openFiles, setOpenFiles] = useState<OpenFile[]>([])
  const [activeFile, setActiveFile] = useState<string>('')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [expandedKeys, setExpandedKeys] = useState<string[]>([])

  // 漏洞标记状态
  const [findingMarks, setFindingMarks] = useState<Record<string, FindingMark>>({})
  const [markingFindingId, setMarkingFindingId] = useState<string | null>(null)
  const [markForm, setMarkForm] = useState<FindingMark>({ type: 'issue', note: '' })

  // 面板宽度状态（可拖拽调整）
  const [siderWidth, setSiderWidth] = useState(320)
  const [reviewWidth, setReviewWidth] = useState(380)
  const [detailHeight, setDetailHeight] = useState(200)
  const [detailPanelOpen, setDetailPanelOpen] = useState(true)
  const [isDragging, setIsDragging] = useState(false)
  const dragRef = useRef<{ target: 'sider' | 'review' | 'detail'; startX: number; startY: number; startWidth: number; startHeight: number } | null>(null)

  // AI Review 状态
  const [reviewPanelOpen, setReviewPanelOpen] = useState(false)
  const [reviewSession, setReviewSession] = useState<ReviewSession | null>(null)
  const [sessionList, setSessionList] = useState<Array<{ id: string; is_active: boolean; created_at: string }>>([])
  const [reviewFinding, setReviewFinding] = useState<Finding | null>(null)
  const [showSessionHistory, setShowSessionHistory] = useState(false)
  const [chatInput, setChatInput] = useState('')
  const [sending, setSending] = useState(false)
  const [streamingStatus, setStreamingStatus] = useState<string>('')
  const [addFindingVisible, setAddFindingVisible] = useState(false)
  const [addFindingForm, setAddFindingForm] = useState({
    title: '', severity: 'HIGH', category: '', location: '',
    description: '', proof: '', attack_scenario: '', code_snippet: '', recommendation: ''
  })

  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null)
  const monacoRef = useRef<Monaco | null>(null)
  const decorationsRef = useRef<string[]>([])
  const jumpDecorationsRef = useRef<string[]>([])
  const jumpTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // 用于在 Monaco 回调中访问最新状态
  const openFilesRef = useRef<OpenFile[]>([])
  const filesRef = useRef<Array<{ path: string; name: string }>>([])
  const projectIdRef = useRef<string>('')
  const activeFileRef = useRef<string>('')

  const chatContainerRef = useRef<HTMLDivElement>(null)

  // 同步 refs
  useEffect(() => { openFilesRef.current = openFiles }, [openFiles])
  useEffect(() => { filesRef.current = files }, [files])
  useEffect(() => { projectIdRef.current = projectId }, [projectId])
  useEffect(() => { activeFileRef.current = activeFile }, [activeFile])

  // 面板拖拽调整大小
  const rafRef = useRef<number>(0)
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!dragRef.current) return
      e.preventDefault()
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
      rafRef.current = requestAnimationFrame(() => {
        if (!dragRef.current) return
        const { target, startX, startY, startWidth, startHeight } = dragRef.current
        if (target === 'detail') {
          const deltaY = startY - e.clientY
          setDetailHeight(Math.max(100, Math.min(500, startHeight + deltaY)))
        } else {
          const delta = e.clientX - startX
          if (target === 'sider') {
            setSiderWidth(Math.max(200, Math.min(500, startWidth + delta)))
          } else {
            setReviewWidth(Math.max(280, Math.min(600, startWidth - delta)))
          }
        }
      })
    }
    const handleMouseUp = () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
      dragRef.current = null
      setIsDragging(false)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [])

  const startDrag = (target: 'sider' | 'review' | 'detail', e: React.MouseEvent) => {
    e.preventDefault()
    dragRef.current = {
      target,
      startX: e.clientX,
      startY: e.clientY,
      startWidth: target === 'sider' ? siderWidth : reviewWidth,
      startHeight: detailHeight,
    }
    setIsDragging(true)
    document.body.style.cursor = target === 'detail' ? 'row-resize' : 'col-resize'
    document.body.style.userSelect = 'none'
  }

  // AI Review: 面板打开时加载会话列表，恢复最近会话或创建新会话
  useEffect(() => {
    if (reviewPanelOpen && reportId && !reviewSession) {
      reviewApi.listSessions(reportId).then(async (data) => {
        setSessionList(data.items || [])
        // 恢复最近的活跃会话
        const activeSession = (data.items || []).find((s: { is_active: boolean }) => s.is_active)
        if (activeSession) {
          const sess = await reviewApi.getSession(activeSession.id)
          setReviewSession(sess)
          // 恢复上次聚焦的漏洞
          if (sess.focused_finding_id) {
            const f = findings.find(item => item.id === sess.focused_finding_id)
            if (f) setReviewFinding(f)
          }
        } else {
          // 没有活跃会话则创建新的
          const sess = await reviewApi.createSession({ report_id: reportId })
          setReviewSession(sess)
          setSessionList(prev => [{ id: sess.id, is_active: true, created_at: new Date().toISOString() }, ...prev])
        }
      }).catch((err) => {
        message.error('加载会话失败: ' + (err.response?.data?.detail || err.message))
      })
    }
  }, [reviewPanelOpen, reportId])

  // AI Review: finding_id 随聊天消息发送，无需提前 focus API

  // AI Review: 自动滚动聊天到底部
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight
    }
  }, [reviewSession?.messages])

  // 加载报告和项目数据
  useEffect(() => {
    if (reportId) {
      loadData()
    }
  }, [reportId])

  // URL 参数中的文件路径
  useEffect(() => {
    const filePath = searchParams.get('file')
    if (filePath && files.length > 0) {
      openFile(filePath)
    }
  }, [searchParams, files])

  const loadData = async () => {
    try {
      setLoading(true)

      // 获取报告详情
      const report = await reportApi.get(reportId!)

      // 获取报告关联的审计任务，从中获取项目ID
      const auditId = report.audit_id
      if (!auditId) {
        message.error('报告未关联审计任务')
        return
      }

      // 通过审计 API 获取项目信息
      const audit = await auditApi.get(auditId)
      const pid = audit.project_id
      setProjectId(pid)
      setProjectName(audit.project_name || 'Unknown')

      // 获取项目文件列表
      const projectFiles = await projectApi.getFiles(pid)
      setFiles(projectFiles)

      // 展开所有目录
      const allDirs = new Set<string>()
      projectFiles.forEach((f) => {
        const parts = f.path.split('/')
        let path = ''
        for (let i = 0; i < parts.length - 1; i++) {
          path = path ? `${path}/${parts[i]}` : parts[i]
          allDirs.add(path)
        }
      })
      setExpandedKeys(Array.from(allDirs))

      // 获取漏洞列表
      const findingsRes = await reportApi.getFindings(reportId!, { limit: 100 })
      setFindings(findingsRes.items || [])

      // 加载已有标记
      try {
        const marks = await reviewApi.getMarks(reportId!)
        const converted: Record<string, FindingMark> = {}
        for (const [fid, m] of Object.entries(marks)) {
          converted[fid] = {
            type: m.mark_type as FindingMarkType,
            severity: m.severity as 'high' | 'medium' | undefined,
            note: m.note || '',
          }
        }
        setFindingMarks(converted)
      } catch { /* 标记加载失败不影响主流程 */ }

      // 自动打开第一个漏洞相关的文件
      const firstMoveFile = projectFiles.find((f) => f.name.endsWith('.move'))
      const defaultFile = firstMoveFile || projectFiles[0]

      if (findingsRes.items?.length > 0) {
        const firstFinding = findingsRes.items[0]
        setSelectedFinding(firstFinding)

        const loc = parseLocation(firstFinding.location)
        let matched = loc ? findMatchingFile(loc.candidates, projectFiles) : null

        // Fallback: 从 code_snippet/title 提取候选
        if (!matched) {
          const fallback = extractCandidatesFromFinding(firstFinding)
          if (fallback.candidates.length > 0) {
            matched = findMatchingFile(fallback.candidates, projectFiles)
          }
        }

        // Fallback: 按函数名搜索文件内容
        const funcName = loc?.func || extractCandidatesFromFinding(firstFinding).funcName
        if (!matched && funcName && pid) {
          for (const f of projectFiles) {
            try {
              const content = await projectApi.getFileContent(pid, f.path)
              const line = findFunctionInCode(content, funcName)
              if (line > 1) {
                matched = f
                break
              }
            } catch { /* skip */ }
          }
        }

        await openFile(matched?.path || defaultFile?.path || '', pid)
      } else if (defaultFile) {
        await openFile(defaultFile.path, pid)
      }
    } catch (error) {
      console.error('Failed to load data:', error)
      message.error('加载数据失败')
    } finally {
      setLoading(false)
    }
  }

  const openFile = async (filePath: string, pid?: string) => {
    const resolvedProjectId = pid || projectIdRef.current || projectId
    if (!resolvedProjectId) return

    // 检查是否已打开
    const existing = openFilesRef.current.find((f) => f.path === filePath)
    if (existing) {
      setActiveFile(filePath)
      return
    }

    try {
      const content = await projectApi.getFileContent(resolvedProjectId, filePath)
      const fileName = filePath.split('/').pop() || filePath

      setOpenFiles((prev) => [...prev, { path: filePath, name: fileName, content }])
      setActiveFile(filePath)
    } catch (error) {
      console.error('Failed to load file:', error)
    }
  }

  const closeFile = (filePath: string) => {
    setOpenFiles((prev) => prev.filter((f) => f.path !== filePath))
    if (activeFile === filePath) {
      const remaining = openFiles.filter((f) => f.path !== filePath)
      setActiveFile(remaining.length > 0 ? remaining[remaining.length - 1].path : '')
    }
  }

  // 跳转到指定行并高亮
  const goToLine = useCallback((lineNumber: number, highlight = true) => {
    const editor = editorRef.current
    const monaco = monacoRef.current

    if (!editor || !monaco) return

    // 跳转到行
    editor.revealLineInCenter(lineNumber)
    editor.setPosition({ lineNumber, column: 1 })

    // 高亮行
    if (highlight) {
      // 清除旧的装饰
      decorationsRef.current = editor.deltaDecorations(decorationsRef.current, [])

      // 添加新的高亮装饰
      decorationsRef.current = editor.deltaDecorations([], [
        {
          range: new monaco.Range(lineNumber, 1, lineNumber, 1),
          options: {
            isWholeLine: true,
            className: 'vulnerability-line-highlight',
            glyphMarginClassName: 'vulnerability-glyph',
          },
        },
      ])
    }
  }, [])

  // 跳转定义时的高亮效果（黄色闪烁，2.5秒后淡出）
  const highlightJumpTarget = useCallback((lineNumber: number) => {
    const ed = editorRef.current
    const monaco = monacoRef.current
    if (!ed || !monaco) return

    // 清除之前的跳转高亮
    if (jumpTimerRef.current) {
      clearTimeout(jumpTimerRef.current)
      jumpTimerRef.current = null
    }
    jumpDecorationsRef.current = ed.deltaDecorations(jumpDecorationsRef.current, [])

    // 跳转到目标行
    ed.revealLineInCenter(lineNumber)
    ed.setPosition({ lineNumber, column: 1 })

    // 添加跳转高亮（3行范围，更容易看到）
    jumpDecorationsRef.current = ed.deltaDecorations([], [
      {
        range: new monaco.Range(lineNumber, 1, lineNumber, 1),
        options: {
          isWholeLine: true,
          className: 'jump-target-highlight',
          glyphMarginClassName: 'jump-target-glyph',
          overviewRuler: {
            color: '#ffd700',
            position: 1, // Center
          },
        },
      },
    ])

    // 2.5秒后淡出
    jumpTimerRef.current = setTimeout(() => {
      if (editorRef.current) {
        jumpDecorationsRef.current = editorRef.current.deltaDecorations(jumpDecorationsRef.current, [])
      }
      jumpTimerRef.current = null
    }, 2500)
  }, [])

  // 根据 location candidates 查找匹配的文件
  const findMatchingFile = (candidates: string[], fileList: Array<{ path: string; name: string }>) => {
    for (const candidate of candidates) {
      const lower = candidate.toLowerCase()
      const match = fileList.find((f) =>
        f.name.toLowerCase().replace('.move', '') === lower ||
        f.path.toLowerCase().includes(lower + '.move')
      )
      if (match) return match
    }
    // fallback: 宽松匹配
    for (const candidate of candidates) {
      const lower = candidate.toLowerCase()
      const match = fileList.find((f) => f.path.toLowerCase().includes(lower))
      if (match) return match
    }
    return null
  }

  // 从 code_snippet 或 title 提取候选文件/函数名
  const extractCandidatesFromFinding = (finding: Finding): { candidates: string[]; funcName: string } => {
    const candidates: string[] = []
    let funcName = ''

    // 从 code_snippet 提取 module 名和 function 名
    if (finding.code_snippet) {
      const moduleMatch = finding.code_snippet.match(/module\s+(?:\w+::)?(\w+)/)
      if (moduleMatch) candidates.push(moduleMatch[1])

      const funMatches = finding.code_snippet.matchAll(/\b(?:public\s+)?(?:entry\s+)?fun\s+(\w+)/g)
      for (const m of funMatches) {
        if (!funcName) funcName = m[1]
        candidates.push(m[1])
      }
    }

    // 从 title 提取可能的函数名 (常见模式: "xxx漏洞" 或 英文函数名)
    if (finding.title) {
      const titleFuncMatch = finding.title.match(/\b([a-z_][a-z0-9_]+)\b/gi)
      if (titleFuncMatch) {
        for (const name of titleFuncMatch) {
          if (name.length > 3 && !['the', 'and', 'for', 'with'].includes(name.toLowerCase())) {
            candidates.push(name)
          }
        }
      }
    }

    return { candidates: [...new Set(candidates)], funcName }
  }

  // 通过函数名在文件内容中搜索，找到包含该函数定义的文件
  const findFileByFuncContent = async (funcName: string, fileList: Array<{ path: string; name: string }>) => {
    // 先搜索已打开的文件
    for (const f of openFilesRef.current) {
      const line = findFunctionInCode(f.content, funcName)
      if (line > 1) return { path: f.path, name: f.name, line }
    }
    // 逐个加载未打开的文件搜索
    for (const f of fileList) {
      if (openFilesRef.current.find((o) => o.path === f.path)) continue
      try {
        const content = await projectApi.getFileContent(projectIdRef.current, f.path)
        const line = findFunctionInCode(content, funcName)
        if (line > 1) return { path: f.path, name: f.name, line }
      } catch { /* skip */ }
    }
    return null
  }

  // 点击漏洞
  const handleFindingClick = async (finding: Finding) => {
    setSelectedFinding(finding)
    setDetailPanelOpen(true)

    const loc = parseLocation(finding.location)
    let matchingFile: { path: string; name: string } | null = null
    let funcToFind = loc?.func || ''

    // 1. 尝试按文件名匹配
    if (loc) {
      matchingFile = findMatchingFile(loc.candidates, filesRef.current)
    }

    // 2. Fallback: 从 code_snippet/title 提取候选名匹配
    if (!matchingFile) {
      const fallback = extractCandidatesFromFinding(finding)
      if (fallback.candidates.length > 0) {
        matchingFile = findMatchingFile(fallback.candidates, filesRef.current)
      }
      if (!funcToFind) funcToFind = fallback.funcName
    }

    // 3. Fallback: 按函数名搜索文件内容
    if (!matchingFile && funcToFind) {
      const found = await findFileByFuncContent(funcToFind, filesRef.current)
      if (found) {
        matchingFile = { path: found.path, name: found.name }
        await openFile(found.path)
        setTimeout(() => goToLine(found.line, true), 200)
        return
      }
    }

    if (!matchingFile) return

    // 确保文件已打开
    const existingFile = openFilesRef.current.find((f) => f.path === matchingFile!.path)
    if (!existingFile) {
      await openFile(matchingFile.path)
    } else {
      setActiveFile(matchingFile.path)
    }

    // 等待编辑器更新后跳转
    setTimeout(() => {
      const file = openFilesRef.current.find((f) => f.path === matchingFile!.path)
      if (file && funcToFind) {
        const lineNumber = findFunctionInCode(file.content, funcToFind)
        goToLine(lineNumber, true)
      }
    }, 200)
  }

  // AI Review: 发送消息 (流式)
  const handleSendMessage = async () => {
    if (!chatInput.trim() || !reviewSession || sending) return
    const userMessage = chatInput.trim()
    setSending(true)
    setStreamingStatus('正在连接...')
    setChatInput('')

    // 乐观更新: 立即显示用户消息
    setReviewSession(prev => {
      if (!prev) return prev
      return {
        ...prev,
        messages: [
          ...(prev.messages || []),
          { id: `temp-${Date.now()}`, role: 'user', content: userMessage, created_at: new Date().toISOString() }
        ]
      }
    })

    reviewApi.chatStream(
      reviewSession.id,
      userMessage,
      // onProgress
      (event) => {
        if (event.type === 'thinking') {
          setStreamingStatus(event.content.length > 60 ? event.content.slice(0, 60) + '...' : event.content)
        } else if (event.type === 'tool_call') {
          const roundInfo = event.round ? ` (${event.round}/${event.total_rounds})` : ''
          setStreamingStatus(`🔧 ${event.content}${roundInfo}`)
        } else if (event.type === 'complete') {
          setStreamingStatus('正在生成回复...')
        }
      },
      // onComplete
      async (content) => {
        setStreamingStatus('')
        setSending(false)
        // 乐观更新: 立即显示 AI 回复
        setReviewSession(prev => {
          if (!prev) return prev
          return {
            ...prev,
            messages: [
              ...(prev.messages || []),
              { id: `ai-${Date.now()}`, role: 'assistant', content, created_at: new Date().toISOString() }
            ]
          }
        })
      },
      // onError
      (error) => {
        setStreamingStatus('')
        setSending(false)
        message.error(error || '发送消息失败')
      },
      // findingId
      reviewFinding?.id
    )
  }

  // 漏洞标记: 提交 (持久化到后端)
  const handleMarkSubmit = async (findingId: string) => {
    try {
      await reviewApi.saveMark(reportId!, {
        finding_id: findingId,
        mark_type: markForm.type,
        severity: markForm.type === 'issue' ? (markForm.severity || 'high') : undefined,
        note: markForm.note,
      })
      setFindingMarks(prev => ({ ...prev, [findingId]: { ...markForm } }))
      setMarkingFindingId(null)
      message.success('标记成功')
    } catch {
      message.error('标记保存失败')
    }
  }

  // 漏洞标记: popover 内容
  const renderMarkPopover = (findingId: string) => (
    <div style={{ width: 260 }}>
      <div className="text-sm font-medium mb-2">审计标记</div>
      <Radio.Group
        value={markForm.type}
        onChange={(e) => setMarkForm(prev => ({ ...prev, type: e.target.value }))}
        className="mb-2"
      >
        <Radio value="issue">是问题</Radio>
        <Radio value="not_issue">不是问题</Radio>
        <Radio value="legacy">遗留问题</Radio>
      </Radio.Group>
      {markForm.type === 'issue' && (
        <div className="mb-2">
          <Radio.Group
            value={markForm.severity || 'high'}
            onChange={(e) => setMarkForm(prev => ({ ...prev, severity: e.target.value }))}
            size="small"
          >
            <Radio value="high">高</Radio>
            <Radio value="medium">中</Radio>
          </Radio.Group>
        </div>
      )}
      <Input.TextArea
        value={markForm.note}
        onChange={(e) => setMarkForm(prev => ({ ...prev, note: e.target.value }))}
        placeholder="请填写审计备注"
        rows={3}
        className="mb-2"
      />
      <div className="text-right">
        <Button type="primary" size="small" onClick={() => handleMarkSubmit(findingId)}>
          提交
        </Button>
      </div>
    </div>
  )

  // Session 管理: 新建会话
  const handleNewSession = async () => {
    if (!reportId) return
    try {
      const sess = await reviewApi.createSession({ report_id: reportId })
      setReviewSession(sess)
      setSessionList(prev => [{ id: sess.id, is_active: true, created_at: new Date().toISOString() }, ...prev])
      setShowSessionHistory(false)
      message.success('新建会话成功')
    } catch {
      message.error('新建会话失败')
    }
  }

  // Session 管理: 切换会话
  const handleSwitchSession = async (sessionId: string) => {
    try {
      const sess = await reviewApi.getSession(sessionId)
      setReviewSession(sess)
      setShowSessionHistory(false)
    } catch {
      message.error('加载会话失败')
    }
  }

  // Session 管理: 删除会话
  const handleDeleteSession = async (sessionId: string) => {
    try {
      await reviewApi.deleteSession(sessionId)
      setSessionList(prev => prev.filter(s => s.id !== sessionId))
      if (reviewSession?.id === sessionId) {
        setReviewSession(null)
        // 自动切换到下一个会话或创建新会话
        const remaining = sessionList.filter(s => s.id !== sessionId)
        if (remaining.length > 0) {
          handleSwitchSession(remaining[0].id)
        } else {
          handleNewSession()
        }
      }
      message.success('会话已删除')
    } catch {
      message.error('删除失败')
    }
  }

  // 确认添加 AI 提取的漏洞到报告
  const handleAddFinding = async () => {
    if (!reportId || !addFindingForm.title.trim()) return
    try {
      await reportApi.addFinding(reportId, {
        title: addFindingForm.title,
        severity: addFindingForm.severity,
        category: addFindingForm.category || undefined,
        description: addFindingForm.description,
        location: addFindingForm.location ? (() => {
          const parts = addFindingForm.location.split('::')
          return parts.length >= 2
            ? { module: parts[0], function: parts.slice(1).join('::') }
            : { module: addFindingForm.location }
        })() : undefined,
        code_snippet: addFindingForm.code_snippet || undefined,
        recommendation: addFindingForm.recommendation || undefined,
        proof: addFindingForm.proof || undefined,
        attack_scenario: addFindingForm.attack_scenario || undefined,
      })
      message.success('漏洞已添加到报告')
      setAddFindingVisible(false)
      setAddFindingForm({
        title: '', severity: 'HIGH', category: '', location: '',
        description: '', proof: '', attack_scenario: '', code_snippet: '', recommendation: ''
      })
      // 刷新漏洞列表
      const findingsRes = await reportApi.getFindings(reportId, { limit: 100 })
      setFindings(findingsRes.items || [])
    } catch {
      message.error('添加失败')
    }
  }

  // 从 AI 回复中提取结构化漏洞（调用后端 AI 提取）
  const handleAddFindingFromChat = async (aiContent: string) => {
    setAddFindingVisible(true)
    setAddFindingForm({
      title: '', severity: 'HIGH', category: '', location: '',
      description: '正在提取...', proof: '', attack_scenario: '', code_snippet: '', recommendation: ''
    })

    try {
      const extracted = await reviewApi.extractFinding(aiContent)
      setAddFindingForm({
        title: extracted.title || '',
        severity: extracted.severity || 'HIGH',
        category: extracted.category || '',
        location: extracted.location || '',
        description: extracted.description || '',
        proof: extracted.proof || '',
        attack_scenario: extracted.attack_scenario || '',
        code_snippet: extracted.code_snippet || '',
        recommendation: extracted.recommendation || '',
      })
    } catch {
      message.error('AI 提取失败，请手动填写')
      setAddFindingForm({
        title: '', severity: 'HIGH', category: '', location: '',
        description: aiContent.slice(0, 500), proof: '', attack_scenario: '', code_snippet: '', recommendation: ''
      })
    }
  }

  // Monaco Editor 挂载回调
  const handleEditorDidMount = (editor: editor.IStandaloneCodeEditor, monaco: Monaco) => {
    editorRef.current = editor
    monacoRef.current = monaco

    // 注册 Move 语言（简单版本）
    monaco.languages.register({ id: 'move' })
    monaco.languages.setMonarchTokensProvider('move', {
      keywords: [
        'module', 'struct', 'public', 'fun', 'entry', 'native', 'const', 'let', 'mut',
        'if', 'else', 'while', 'loop', 'return', 'abort', 'break', 'continue',
        'true', 'false', 'as', 'use', 'friend', 'has', 'copy', 'drop', 'store', 'key',
        'acquires', 'move', 'phantom', 'spec', 'requires', 'ensures', 'aborts_if',
        'assert', 'assume', 'invariant', 'pragma',
      ],
      typeKeywords: [
        'u8', 'u16', 'u32', 'u64', 'u128', 'u256', 'bool', 'address', 'signer', 'vector',
      ],
      operators: [
        '=', '>', '<', '!', '~', '?', ':', '==', '<=', '>=', '!=',
        '&&', '||', '++', '--', '+', '-', '*', '/', '&', '|', '^', '%',
        '<<', '>>', '+=', '-=', '*=', '/=', '&=', '|=', '^=',
      ],
      symbols: /[=><!~?:&|+\-*\/\^%]+/,
      tokenizer: {
        root: [
          [/[a-z_$][\w$]*/, {
            cases: {
              '@keywords': 'keyword',
              '@typeKeywords': 'type',
              '@default': 'identifier',
            },
          }],
          [/[A-Z][\w$]*/, 'type.identifier'],
          { include: '@whitespace' },
          [/[{}()\[\]]/, '@brackets'],
          [/@symbols/, {
            cases: {
              '@operators': 'operator',
              '@default': '',
            },
          }],
          [/\d*\.\d+([eE][\-+]?\d+)?/, 'number.float'],
          [/0[xX][0-9a-fA-F]+/, 'number.hex'],
          [/\d+/, 'number'],
          [/[;,.]/, 'delimiter'],
          [/"([^"\\]|\\.)*$/, 'string.invalid'],
          [/"/, { token: 'string.quote', bracket: '@open', next: '@string' }],
        ],
        string: [
          [/[^\\"]+/, 'string'],
          [/\\./, 'string.escape'],
          [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }],
        ],
        whitespace: [
          [/[ \t\r\n]+/, 'white'],
          [/\/\*/, 'comment', '@comment'],
          [/\/\/.*$/, 'comment'],
        ],
        comment: [
          [/[^\/*]+/, 'comment'],
          [/\/\*/, 'comment', '@push'],
          [/\*\//, 'comment', '@pop'],
          [/[\/*]/, 'comment'],
        ],
      },
    })

    // 定义 Move 语言主题
    monaco.editor.defineTheme('move-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: '569CD6', fontStyle: 'bold' },
        { token: 'type', foreground: '4EC9B0' },
        { token: 'type.identifier', foreground: '4EC9B0' },
        { token: 'comment', foreground: '6A9955' },
        { token: 'string', foreground: 'CE9178' },
        { token: 'number', foreground: 'B5CEA8' },
      ],
      colors: {
        'editor.background': '#1e1e1e',
      },
    })

    monaco.editor.setTheme('move-dark')

    // 跳过关键字列表
    const skipKeywords = ['if', 'else', 'while', 'loop', 'return', 'let', 'mut', 'public', 'fun', 'entry', 'module', 'struct', 'use', 'const', 'true', 'false', 'has', 'copy', 'drop', 'store', 'key', 'abort', 'break', 'continue', 'as', 'friend', 'native', 'spec', 'requires', 'ensures', 'assert']

    // 搜索符号定义的通用函数
    const findDefinition = (symbolName: string, content: string) => {
      const patterns = [
        new RegExp(`\\b(public(\\s*\\(\\w+\\))?\\s+)?(entry\\s+)?fun\\s+${symbolName}\\b`),
        new RegExp(`\\b(public\\s+)?struct\\s+${symbolName}\\b`),
        new RegExp(`\\bconst\\s+${symbolName}\\b`),
      ]
      const lines = content.split('\n')
      for (let i = 0; i < lines.length; i++) {
        for (const pattern of patterns) {
          if (pattern.test(lines[i])) {
            return i + 1 // 返回行号 (1-based)
          }
        }
      }
      return -1
    }

    // 注册定义提供者 - 提供 Cmd+Hover 时的下划线提示
    monaco.languages.registerDefinitionProvider('move', {
      provideDefinition: (model: editor.ITextModel, position: Position) => {
        const word = model.getWordAtPosition(position)
        if (!word) return null
        const symbolName = word.word
        if (skipKeywords.includes(symbolName)) return null

        const currentOpenFiles = openFilesRef.current

        // 搜索定义位置
        for (const file of currentOpenFiles) {
          const lineNumber = findDefinition(symbolName, file.content)
          if (lineNumber > 0) {
            // 始终返回当前 model 的 URI，让 Monaco 显示下划线
            return {
              uri: model.uri,
              range: new monaco.Range(lineNumber, 1, lineNumber, 1),
            }
          }
        }
        return null
      },
    })

    // Cmd+Click 跳转处理 - 通过 mouseDown 事件实现实际导航
    editor.onMouseDown(async (e) => {
      // 检测 Cmd (Mac) 或 Ctrl (Windows/Linux) + 点击
      if (!(e.event.metaKey || e.event.ctrlKey)) return
      if (!e.target.position) return

      const model = editor.getModel()
      if (!model) return

      const word = model.getWordAtPosition(e.target.position)
      if (!word) return

      const symbolName = word.word
      if (skipKeywords.includes(symbolName)) return

      const currentOpenFiles = openFilesRef.current
      const currentFiles = filesRef.current
      const currentProjectId = projectIdRef.current
      const currentActiveFile = activeFileRef.current

      // 1. 在已打开的文件中搜索定义
      for (const file of currentOpenFiles) {
        const lineNumber = findDefinition(symbolName, file.content)
        if (lineNumber > 0) {
          if (file.path !== currentActiveFile) {
            setActiveFile(file.path)
            // 等待编辑器切换文件后跳转并高亮
            setTimeout(() => highlightJumpTarget(lineNumber), 200)
          } else {
            highlightJumpTarget(lineNumber)
          }
          return
        }
      }

      // 2. 在所有项目文件中搜索（尚未打开的文件）
      for (const file of currentFiles) {
        if (currentOpenFiles.some(f => f.path === file.path)) continue

        try {
          const content = await projectApi.getFileContent(currentProjectId, file.path)
          const lineNumber = findDefinition(symbolName, content)
          if (lineNumber > 0) {
            // 打开新文件并跳转高亮
            const fileName = file.path.split('/').pop() || file.path
            setOpenFiles(prev => [...prev, { path: file.path, name: fileName, content }])
            setActiveFile(file.path)
            setTimeout(() => highlightJumpTarget(lineNumber), 250)
            return
          }
        } catch (e2) {
          console.error('Failed to search file:', file.path, e2)
        }
      }
    })

    // 注册悬停提示 - 显示函数/结构体签名
    monaco.languages.registerHoverProvider('move', {
      provideHover: (model: editor.ITextModel, position: Position) => {
        const word = model.getWordAtPosition(position)
        if (!word) return null

        const symbolName = word.word

        // 使用 ref 获取最新状态
        const currentOpenFiles = openFilesRef.current

        // 定义模式
        const funcPattern = new RegExp(`\\b(public(\\s*\\(\\w+\\))?\\s+)?(entry\\s+)?fun\\s+${symbolName}\\b`)
        const structPattern = new RegExp(`\\b(public\\s+)?struct\\s+${symbolName}\\b`)
        const constPattern = new RegExp(`\\bconst\\s+${symbolName}\\b`)

        // 在所有文件中搜索定义
        for (const file of currentOpenFiles) {
          const lines = file.content.split('\n')
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i]

            // 检查是否匹配函数定义
            if (funcPattern.test(line)) {
              // 提取函数签名（到 { 为止）
              let signature = line.trim()
              let j = i + 1
              while (!signature.includes('{') && j < lines.length) {
                signature += ' ' + lines[j].trim()
                j++
              }
              signature = signature.split('{')[0].trim()

              return {
                range: new monaco.Range(position.lineNumber, word.startColumn, position.lineNumber, word.endColumn),
                contents: [
                  { value: `**函数** - ${file.name}` },
                  { value: '```move\n' + signature + '\n```' },
                  { value: `📍 Line ${i + 1} | Cmd+Click 跳转` },
                ],
              }
            }

            // 检查是否匹配结构体定义
            if (structPattern.test(line)) {
              // 提取结构体签名（包含 abilities 和字段）
              let signature = line.trim()
              let j = i + 1
              let braceCount = (line.match(/{/g) || []).length - (line.match(/}/g) || []).length

              // 提取到结构体定义结束
              while (braceCount > 0 && j < lines.length && j < i + 15) {
                const nextLine = lines[j].trim()
                signature += '\n  ' + nextLine
                braceCount += (nextLine.match(/{/g) || []).length - (nextLine.match(/}/g) || []).length
                j++
              }

              return {
                range: new monaco.Range(position.lineNumber, word.startColumn, position.lineNumber, word.endColumn),
                contents: [
                  { value: `**结构体** - ${file.name}` },
                  { value: '```move\n' + signature + '\n```' },
                  { value: `📍 Line ${i + 1} | Cmd+Click 跳转` },
                ],
              }
            }

            // 检查是否匹配常量定义
            if (constPattern.test(line)) {
              return {
                range: new monaco.Range(position.lineNumber, word.startColumn, position.lineNumber, word.endColumn),
                contents: [
                  { value: `**常量** - ${file.name}` },
                  { value: '```move\n' + line.trim() + '\n```' },
                  { value: `📍 Line ${i + 1} | Cmd+Click 跳转` },
                ],
              }
            }
          }
        }

        return null
      },
    })

    // 右键菜单: 发送选中代码到 AI
    editor.addAction({
      id: 'send-to-ai',
      label: '发送到 AI 对话',
      contextMenuGroupId: '9_cutcopypaste',
      contextMenuOrder: 99,
      precondition: 'editorHasSelection',
      run: (ed) => {
        const selection = ed.getSelection()
        if (!selection) return
        const selectedText = ed.getModel()?.getValueInRange(selection)
        if (!selectedText?.trim()) return

        // 打开 review 面板（如果未开启）
        setReviewPanelOpen(true)

        // 填充到聊天输入
        const codeBlock = `\`\`\`move\n${selectedText.trim()}\n\`\`\`\n请分析这段代码的安全性：`
        setChatInput(codeBlock)
      },
    })

    // 如果有选中的漏洞，跳转到对应位置
    if (selectedFinding) {
      const loc = parseLocation(selectedFinding.location)
      let funcToFind = loc?.func || ''
      if (!funcToFind) {
        const fallback = extractCandidatesFromFinding(selectedFinding)
        funcToFind = fallback.funcName
      }
      const currentFile = openFiles.find((f) => f.path === activeFile)
      if (funcToFind && currentFile) {
        const lineNumber = findFunctionInCode(currentFile.content, funcToFind)
        setTimeout(() => goToLine(lineNumber, true), 100)
      }
    }
  }

  // 文件树数据
  const treeData = buildFileTree(files)

  // 当前打开文件的内容
  const currentFileContent = openFiles.find((f) => f.path === activeFile)?.content || ''

  // 按严重性分组漏洞
  const findingsBySeverity = findings.reduce((acc, f) => {
    const sev = f.severity || 'MEDIUM'
    if (!acc[sev]) acc[sev] = []
    acc[sev].push(f)
    return acc
  }, {} as Record<string, Finding[]>)

  // 排序后的严重性列表
  const sortedSeverities = Object.keys(findingsBySeverity).sort(
    (a, b) => (SEVERITY_CONFIG[a as Severity]?.order ?? 99) - (SEVERITY_CONFIG[b as Severity]?.order ?? 99)
  )

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <Spin size="large" tip="加载中...">
          <div style={{ minHeight: '100px' }} />
        </Spin>
      </div>
    )
  }

  return (
    <Layout className="h-full">
      {/* 左侧边栏 */}
      <Sider width={siderWidth} theme="light" className="overflow-hidden flex flex-col no-transition" style={{ minWidth: siderWidth, maxWidth: siderWidth }}>
        {/* 头部 */}
        <div className="p-3 border-b bg-gray-50">
          {!props.embedded && (
            <Button
              icon={<ArrowLeftOutlined />}
              size="small"
              onClick={() => navigate(`/reports/${reportId}`)}
            >
              返回报告
            </Button>
          )}
          <div className={`${props.embedded ? '' : 'mt-2 '}text-sm text-gray-600 truncate`} title={projectName}>
            项目：{projectName}
          </div>
        </div>

        {/* 标签页：文件 / 漏洞 */}
        <Tabs
          defaultActiveKey="findings"
          className="flex-1 overflow-hidden"
          items={[
            {
              key: 'findings',
              label: (
                <span>
                  <BugOutlined /> 漏洞 ({findings.length})
                </span>
              ),
              children: (
                <div className="overflow-auto" style={{ height: 'calc(100vh - 210px)' }}>
                  {findings.length === 0 ? (
                    <Empty description="无漏洞" className="mt-8" />
                  ) : (
                    <Collapse
                      defaultActiveKey={sortedSeverities}
                      ghost
                      items={sortedSeverities.map((sev) => ({
                        key: sev,
                        label: (
                          <span>
                            <Badge
                              color={SEVERITY_CONFIG[sev as Severity]?.color || '#999'}
                              text={SEVERITY_CONFIG[sev as Severity]?.label || sev}
                            />
                            <span className="ml-2 text-gray-400">
                              ({findingsBySeverity[sev].length})
                            </span>
                          </span>
                        ),
                        children: (
                          <div className="space-y-1">
                            {findingsBySeverity[sev].map((finding) => (
                              <div
                                key={finding.id}
                                className={`p-2 rounded cursor-pointer transition-colors ${
                                  selectedFinding?.id === finding.id
                                    ? 'bg-blue-50 border-l-4 border-blue-500'
                                    : 'hover:bg-gray-50'
                                }`}
                                onClick={() => handleFindingClick(finding)}
                              >
                                <div className="flex items-center justify-between gap-1">
                                  <div className="text-sm font-medium truncate flex-1" title={finding.title}>
                                    {finding.title || '未命名漏洞'}
                                  </div>
                                  <Popover
                                    trigger="click"
                                    open={markingFindingId === finding.id}
                                    onOpenChange={(open) => {
                                      if (open) {
                                        const existing = findingMarks[finding.id]
                                        setMarkForm(existing || { type: 'issue', note: '' })
                                        setMarkingFindingId(finding.id)
                                      } else {
                                        setMarkingFindingId(null)
                                      }
                                    }}
                                    content={renderMarkPopover(finding.id)}
                                    placement="right"
                                  >
                                    <TagOutlined
                                      className="text-gray-400 hover:text-blue-500 flex-shrink-0"
                                      style={{ fontSize: 12 }}
                                      onClick={(e) => e.stopPropagation()}
                                    />
                                  </Popover>
                                </div>
                                <div className="flex items-center gap-1 mt-1">
                                  {finding.location && (
                                    <div className="text-xs text-gray-400 truncate">
                                      <CodeOutlined className="mr-1" />
                                      {finding.location.file}
                                    </div>
                                  )}
                                  {findingMarks[finding.id] && (
                                    <Tag
                                      color={MARK_CONFIG[findingMarks[finding.id].type]?.color}
                                      style={{ fontSize: 10, lineHeight: '16px', padding: '0 4px', margin: 0 }}
                                    >
                                      {MARK_CONFIG[findingMarks[finding.id].type]?.label}
                                    </Tag>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        ),
                      }))}
                    />
                  )}
                </div>
              ),
            },
            {
              key: 'files',
              label: (
                <span>
                  <FolderOutlined /> 文件 ({files.length})
                </span>
              ),
              children: (
                <div className="overflow-auto" style={{ height: 'calc(100vh - 210px)' }}>
                  <Tree
                    showIcon
                    expandedKeys={expandedKeys}
                    onExpand={(keys) => setExpandedKeys(keys as string[])}
                    treeData={treeData}
                    onSelect={(_, { node }) => {
                      if (node.isLeaf) {
                        openFile(node.key as string)
                      }
                    }}
                    selectedKeys={[activeFile]}
                  />
                </div>
              ),
            },
          ]}
        />
      </Sider>

      {/* 左侧拖拽分隔条 */}
      <div
        className="resize-handle"
        onMouseDown={(e) => startDrag('sider', e)}
      />

      {/* 中间代码区 */}
      <Content className="flex flex-col bg-gray-900">
        {/* 文件标签栏 + AI Review 按钮 */}
        <div className="flex bg-gray-800 border-b border-gray-700">
          <div className="flex-1 flex overflow-x-auto">
            {openFiles.map((file) => (
              <div
                key={file.path}
                className={`flex items-center px-3 py-2 cursor-pointer border-r border-gray-700 ${
                  activeFile === file.path
                    ? 'bg-gray-900 text-white'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}
                onClick={() => setActiveFile(file.path)}
              >
                <FileOutlined className="mr-2" />
                <span className="text-sm">{file.name}</span>
                <button
                  className="ml-2 text-gray-500 hover:text-white"
                  onClick={(e) => {
                    e.stopPropagation()
                    closeFile(file.path)
                  }}
                >
                  ×
                </button>
              </div>
            ))}
          </div>
          <Button
            type="primary"
            icon={<CommentOutlined />}
            size="small"
            style={reviewPanelOpen
              ? { margin: '4px 8px', background: '#1677ff' }
              : { margin: '4px 8px', background: '#6366f1', borderColor: '#6366f1' }
            }
            onClick={() => setReviewPanelOpen(!reviewPanelOpen)}
          >
            {reviewPanelOpen ? '关闭 Review' : 'AI Review'}
          </Button>
        </div>

        {/* 代码编辑器 */}
        <div className="flex-1 min-h-0 overflow-hidden">
          {activeFile ? (
            <Editor
              height="100%"
              language="move"
              theme="move-dark"
              value={currentFileContent}
              options={{
                readOnly: true,
                minimap: { enabled: reviewPanelOpen ? false : true },
                fontSize: 14,
                lineNumbers: 'on',
                scrollBeyondLastLine: false,
                wordWrap: 'on',
                glyphMargin: true,
                folding: true,
                renderLineHighlight: 'all',
              }}
              onMount={handleEditorDidMount}
            />
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              <Empty description="选择文件或点击漏洞查看代码" />
            </div>
          )}
        </div>

        {/* 底部漏洞详情 */}
        {selectedFinding && (
          <div className="flex-shrink-0">
            {!detailPanelOpen ? (
              /* 收起时的切换条 */
              <div
                className="bg-gray-800 border-t border-gray-700 px-4 py-2 flex items-center justify-between cursor-pointer hover:bg-gray-700"
                onClick={() => setDetailPanelOpen(true)}
              >
                <div className="flex items-center gap-2 text-gray-400 text-sm">
                  <Tag color={SEVERITY_CONFIG[selectedFinding.severity]?.color} className="m-0">
                    {SEVERITY_CONFIG[selectedFinding.severity]?.label}
                  </Tag>
                  <span className="truncate max-w-md">{selectedFinding.title}</span>
                </div>
                <UpOutlined className="text-gray-400" />
              </div>
            ) : (
              /* 展开时的详情面板 */
              <div style={{ height: detailHeight + 6 }} className="flex flex-col">
                {/* 拖拽手柄 */}
                <div
                  className="h-[6px] bg-gray-700 border-t border-gray-600 cursor-row-resize hover:bg-blue-500 transition-colors flex items-center justify-center flex-shrink-0"
                  onMouseDown={(e) => startDrag('detail', e)}
                >
                  <div className="w-10 h-[2px] bg-gray-500 rounded" />
                </div>
                {/* 头部：标题 + 收起按钮 */}
                <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700 flex-shrink-0">
                  <div className="flex items-center gap-2">
                    <Tag color={SEVERITY_CONFIG[selectedFinding.severity]?.color} className="m-0">
                      {SEVERITY_CONFIG[selectedFinding.severity]?.label}
                    </Tag>
                    <span className="text-white font-medium text-sm">{selectedFinding.title}</span>
                  </div>
                  <Button
                    type="text"
                    size="small"
                    icon={<DownOutlined />}
                    style={{ color: '#9ca3af' }}
                    onClick={() => setDetailPanelOpen(false)}
                  />
                </div>
                {/* 内容 */}
                <div className="flex-1 overflow-auto bg-gray-800 p-4">
                  <div className="text-gray-400 text-sm">{selectedFinding.description}</div>
                  {selectedFinding.recommendation && (
                    <div className="mt-3 p-2 bg-green-900/30 rounded text-green-300 text-sm">
                      <strong>修复建议：</strong>
                      <pre className="whitespace-pre-wrap mt-1">{selectedFinding.recommendation}</pre>
                    </div>
                  )}
                  {selectedFinding.proof && (
                    <div className="mt-3 p-2 bg-yellow-900/30 rounded text-yellow-300 text-sm">
                      <strong>漏洞证明：</strong>
                      <pre className="whitespace-pre-wrap mt-1">{selectedFinding.proof}</pre>
                    </div>
                  )}
                  {selectedFinding.attack_scenario && (
                    <div className="mt-3 p-2 bg-red-900/30 rounded text-red-300 text-sm">
                      <strong>攻击场景：</strong>
                      <pre className="whitespace-pre-wrap mt-1">{selectedFinding.attack_scenario}</pre>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </Content>

      {/* AI Review 右侧面板 */}
      {reviewPanelOpen && (
        <>
        {/* 右侧拖拽分隔条 */}
        <div
          className="resize-handle"
          onMouseDown={(e) => startDrag('review', e)}
        />
        <div className="review-panel flex flex-col bg-gray-900" style={{ width: reviewWidth }}>
          {/* 面板头部：漏洞选择器（可选） */}
          <div className="p-2 border-b border-gray-700 bg-gray-800">
            <Select
              size="small"
              placeholder="不选择漏洞，直接对话"
              value={reviewFinding?.id || undefined}
              allowClear
              onChange={(findingId) => {
                if (!findingId) {
                  setReviewFinding(null)
                  if (reviewSession) reviewApi.focusFinding(reviewSession.id, '').catch(() => {})
                  return
                }
                const finding = findings.find((f: Finding) => f.id === findingId)
                if (finding) {
                  setReviewFinding(finding)
                  handleFindingClick(finding)
                  if (reviewSession) reviewApi.focusFinding(reviewSession.id, findingId).catch(() => {})
                }
              }}
              style={{ width: '100%' }}
              className="review-finding-select"
              popupMatchSelectWidth={false}
              options={findings.map((f: Finding) => ({
                value: f.id,
                label: (
                  <span className="flex items-center gap-1">
                    <span style={{ color: SEVERITY_CONFIG[f.severity]?.color, fontWeight: 600, fontSize: 11 }}>
                      [{SEVERITY_CONFIG[f.severity]?.label}]
                    </span>
                    <span className="truncate">{f.title}</span>
                  </span>
                ),
              }))}
            />
          </div>

          {/* 会话管理栏 */}
          <div className="px-2 py-1 border-b border-gray-700 bg-gray-850 flex items-center justify-between">
            <span className="text-gray-400 text-xs">
              会话 {reviewSession?.id?.slice(0, 8)}...
            </span>
            <div className="flex gap-1">
              <Button size="small" type="text" className="text-gray-400 text-xs" onClick={handleNewSession}>
                新建
              </Button>
              <Button
                size="small"
                type="text"
                className="text-gray-400 text-xs"
                onClick={() => setShowSessionHistory(!showSessionHistory)}
              >
                {showSessionHistory ? '返回' : '历史'}
              </Button>
            </div>
          </div>

          {/* 会话历史列表 */}
          {showSessionHistory ? (
            <div className="flex-1 overflow-auto p-3 space-y-2">
              <div className="text-gray-400 text-xs mb-2">历史会话 ({sessionList.length})</div>
              {sessionList.map((sess) => (
                <div
                  key={sess.id}
                  className={`p-2 rounded border text-xs cursor-pointer ${
                    reviewSession?.id === sess.id
                      ? 'border-blue-500 bg-blue-900/30 text-white'
                      : 'border-gray-700 bg-gray-800 text-gray-300 hover:border-gray-500'
                  }`}
                  onClick={() => handleSwitchSession(sess.id)}
                >
                  <div className="flex items-center justify-between">
                    <span>{sess.id.slice(0, 8)}...</span>
                    <div className="flex items-center gap-1">
                      {sess.is_active && <Tag color="green" style={{ fontSize: 10, lineHeight: '14px', padding: '0 3px', margin: 0 }}>活跃</Tag>}
                      <Button
                        size="small"
                        type="text"
                        danger
                        className="text-xs"
                        style={{ fontSize: 10, height: 18, padding: '0 4px' }}
                        onClick={(e) => { e.stopPropagation(); handleDeleteSession(sess.id) }}
                      >
                        删除
                      </Button>
                    </div>
                  </div>
                  <div className="text-gray-500 mt-1">
                    {formatDateTime(sess.created_at)}
                  </div>
                </div>
              ))}
              {sessionList.length === 0 && (
                <div className="text-center text-gray-500 py-4">暂无历史会话</div>
              )}
            </div>
          ) : (
          <>
          {/* 聊天消息 */}
          <div
            ref={chatContainerRef}
            className="flex-1 overflow-auto p-3 space-y-3"
          >
            {reviewSession?.messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div className="max-w-[85%]">
                  <div
                    className={`rounded-lg px-3 py-2 text-sm ${
                      msg.role === 'user'
                        ? 'bg-blue-600 text-white'
                        : msg.role === 'system'
                        ? 'bg-gray-700 text-gray-300 text-xs'
                        : 'bg-gray-700 text-gray-200'
                    }`}
                  >
                    {msg.role === 'system' && (
                      <div className="text-gray-400 text-xs mb-1">系统</div>
                    )}
                    <div className="whitespace-pre-wrap">{msg.content}</div>
                  </div>
                  {msg.role === 'assistant' && msg.content.length > 50 && (
                    <div className="mt-1">
                      <Button
                        size="small"
                        type="text"
                        icon={<PlusOutlined />}
                        className="text-gray-500 text-xs"
                        style={{ fontSize: 11, height: 20, padding: '0 4px' }}
                        onClick={() => handleAddFindingFromChat(msg.content)}
                      >
                        添加为漏洞
                      </Button>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {(!reviewSession?.messages || reviewSession.messages.length === 0) && (
              <div className="text-center text-gray-500 py-8 text-sm">
                {selectedFinding
                  ? '向 AI 助手提问，例如：这个漏洞是否为误报？'
                  : '选择左侧漏洞后开始对话'}
              </div>
            )}
            {sending && (
              <div className="flex justify-start">
                <div className="bg-gray-700 text-gray-300 rounded-lg px-3 py-2 text-sm max-w-[90%]">
                  <Spin size="small" /> <span className="ml-1">{streamingStatus || '思考中...'}</span>
                </div>
              </div>
            )}
          </div>

          {/* 快捷操作 */}
          <div className="px-3 pt-2 pb-1 border-t border-gray-700 bg-gray-800 flex flex-wrap gap-1">
            {['这个漏洞是否为误报？', '分析攻击路径', '有什么修复建议？', '相关函数的调用链？'].map(q => (
              <Button
                key={q}
                size="small"
                type="dashed"
                className="text-xs text-gray-400"
                style={{ fontSize: 11, height: 22, padding: '0 6px' }}
                onClick={() => { setChatInput(q); }}
              >
                {q}
              </Button>
            ))}
          </div>

          {/* 输入区域 */}
          <div className="px-3 pb-3 bg-gray-800">
            <div className="flex gap-2">
              <TextArea
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="输入问题..."
                autoSize={{ minRows: 1, maxRows: 3 }}
                className="bg-gray-700 border-gray-600 text-white"
                onPressEnter={(e) => {
                  if (!e.shiftKey) {
                    e.preventDefault()
                    handleSendMessage()
                  }
                }}
              />
              <Button
                type="primary"
                icon={<SendOutlined />}
                onClick={handleSendMessage}
                loading={sending}
                disabled={!chatInput.trim()}
              />
            </div>
          </div>
          </>
          )}
        </div>
        </>
      )}

      {/* AI 提取漏洞确认弹窗 */}
      <Modal
        title="AI 提取漏洞 - 确认添加"
        open={addFindingVisible}
        onOk={handleAddFinding}
        onCancel={() => setAddFindingVisible(false)}
        okText="确认添加"
        cancelText="取消"
        okButtonProps={{ disabled: !addFindingForm.title || addFindingForm.description === '正在提取...' }}
        width={640}
      >
        {addFindingForm.description === '正在提取...' ? (
          <div className="text-center py-8">
            <Spin size="large" />
            <div className="mt-3 text-gray-500">AI 正在分析并提取结构化漏洞信息...</div>
          </div>
        ) : (
          <div className="space-y-3" style={{ maxHeight: '60vh', overflowY: 'auto' }}>
            <div className="flex gap-3">
              <div className="flex-1">
                <div className="text-xs text-gray-500 mb-1">漏洞标题</div>
                <Input
                  value={addFindingForm.title}
                  onChange={(e) => setAddFindingForm(prev => ({ ...prev, title: e.target.value }))}
                />
              </div>
              <div style={{ width: 120 }}>
                <div className="text-xs text-gray-500 mb-1">严重性</div>
                <Select
                  value={addFindingForm.severity}
                  onChange={(v) => setAddFindingForm(prev => ({ ...prev, severity: v }))}
                  style={{ width: '100%' }}
                  options={[
                    { value: 'CRITICAL', label: '危急' },
                    { value: 'HIGH', label: '高危' },
                    { value: 'MEDIUM', label: '中危' },
                    { value: 'LOW', label: '低危' },
                    { value: 'ADVISORY', label: '建议' },
                  ]}
                />
              </div>
            </div>
            <div className="flex gap-3">
              <div className="flex-1">
                <div className="text-xs text-gray-500 mb-1">位置 (module::function)</div>
                <Input
                  value={addFindingForm.location}
                  onChange={(e) => setAddFindingForm(prev => ({ ...prev, location: e.target.value }))}
                  placeholder="如 challenge::claim_drop"
                />
              </div>
              <div className="flex-1">
                <div className="text-xs text-gray-500 mb-1">分类</div>
                <Input
                  value={addFindingForm.category}
                  onChange={(e) => setAddFindingForm(prev => ({ ...prev, category: e.target.value }))}
                  placeholder="如 logic, access_control"
                />
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">漏洞描述</div>
              <Input.TextArea
                value={addFindingForm.description}
                onChange={(e) => setAddFindingForm(prev => ({ ...prev, description: e.target.value }))}
                rows={3}
              />
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">漏洞证明</div>
              <Input.TextArea
                value={addFindingForm.proof}
                onChange={(e) => setAddFindingForm(prev => ({ ...prev, proof: e.target.value }))}
                rows={2}
              />
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">攻击场景</div>
              <Input.TextArea
                value={addFindingForm.attack_scenario}
                onChange={(e) => setAddFindingForm(prev => ({ ...prev, attack_scenario: e.target.value }))}
                rows={3}
              />
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">漏洞代码</div>
              <Input.TextArea
                value={addFindingForm.code_snippet}
                onChange={(e) => setAddFindingForm(prev => ({ ...prev, code_snippet: e.target.value }))}
                rows={4}
                style={{ fontFamily: 'monospace', fontSize: 12 }}
              />
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">修复建议</div>
              <Input.TextArea
                value={addFindingForm.recommendation}
                onChange={(e) => setAddFindingForm(prev => ({ ...prev, recommendation: e.target.value }))}
                rows={3}
              />
            </div>
          </div>
        )}
      </Modal>

      {/* 拖拽时覆盖层，防止编辑器抢占鼠标事件 */}
      {isDragging && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 9999, cursor: 'col-resize' }} />
      )}

      {/* 添加样式 */}
      <style>{`
        .vulnerability-line-highlight {
          background-color: rgba(255, 0, 0, 0.2) !important;
          border-left: 3px solid #ff4d4f !important;
        }
        .vulnerability-glyph {
          background-color: #ff4d4f;
          border-radius: 50%;
          margin-left: 5px;
        }
        .jump-target-highlight {
          background-color: rgba(255, 215, 0, 0.35) !important;
          border-left: 3px solid #ffd700 !important;
          animation: jump-flash 2.5s ease-out forwards;
        }
        .jump-target-glyph {
          background-color: #ffd700;
          border-radius: 50%;
          margin-left: 5px;
          animation: jump-glyph-flash 2.5s ease-out forwards;
        }
        @keyframes jump-flash {
          0% {
            background-color: rgba(255, 215, 0, 0.5) !important;
            border-left-color: #ffd700 !important;
          }
          30% {
            background-color: rgba(255, 215, 0, 0.35) !important;
          }
          100% {
            background-color: rgba(255, 215, 0, 0.08) !important;
            border-left-color: rgba(255, 215, 0, 0.3) !important;
          }
        }
        @keyframes jump-glyph-flash {
          0% { opacity: 1; }
          100% { opacity: 0.2; }
        }
        .review-panel .ant-input,
        .review-panel .ant-input-textarea textarea {
          background-color: #374151 !important;
          border-color: #4b5563 !important;
          color: #e5e7eb !important;
        }
        .review-panel .ant-input::placeholder,
        .review-panel .ant-input-textarea textarea::placeholder {
          color: #9ca3af !important;
        }
        .line-clamp-2 {
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }
        .ant-tabs-content {
          height: 100%;
        }
        .ant-tabs-tabpane {
          height: 100%;
        }
      `}</style>
    </Layout>
  )
}
