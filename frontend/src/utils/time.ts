/**
 * 时间格式化工具
 * 统一使用北京时间 (Asia/Shanghai, UTC+8)
 */

/**
 * 格式化日期时间为北京时间
 * @param date 日期字符串或 Date 对象
 * @param showSeconds 是否显示秒，默认 true
 * @returns 格式化后的北京时间字符串
 */
export function formatDateTime(date: string | Date, showSeconds = true): string {
  const d = typeof date === 'string' ? new Date(date) : date

  const options: Intl.DateTimeFormatOptions = {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }

  if (showSeconds) {
    options.second = '2-digit'
  }

  return d.toLocaleString('zh-CN', options)
}

/**
 * 格式化日期为北京时间（不含时间）
 * @param date 日期字符串或 Date 对象
 * @returns 格式化后的日期字符串
 */
export function formatDate(date: string | Date): string {
  const d = typeof date === 'string' ? new Date(date) : date

  return d.toLocaleDateString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
}

/**
 * 格式化时间为北京时间（不含日期）
 * @param date 日期字符串或 Date 对象
 * @returns 格式化后的时间字符串
 */
export function formatTime(date: string | Date): string {
  const d = typeof date === 'string' ? new Date(date) : date

  return d.toLocaleTimeString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

/**
 * 获取相对时间描述
 * @param date 日期字符串或 Date 对象
 * @returns 相对时间描述，如 "刚刚"、"5分钟前"、"2小时前" 等
 */
export function formatRelativeTime(date: string | Date): string {
  const d = typeof date === 'string' ? new Date(date) : date
  const now = new Date()
  const diff = now.getTime() - d.getTime()

  const seconds = Math.floor(diff / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)

  if (seconds < 60) {
    return '刚刚'
  } else if (minutes < 60) {
    return `${minutes}分钟前`
  } else if (hours < 24) {
    return `${hours}小时前`
  } else if (days < 7) {
    return `${days}天前`
  } else {
    return formatDateTime(d, false)
  }
}
