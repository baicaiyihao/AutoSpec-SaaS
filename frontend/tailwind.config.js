/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // 严重性颜色
        severity: {
          critical: '#ff4d4f',
          high: '#ff7a45',
          medium: '#ffc53d',
          low: '#73d13d',
          advisory: '#1890ff',
        },
      },
    },
  },
  plugins: [],
  // 与 Ant Design 兼容
  corePlugins: {
    preflight: false,
  },
}
