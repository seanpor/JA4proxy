/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: '#1f2937',
        secondary: '#374151',
        accent: '#3b82f6',
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#10b981',
        info: '#06b6d4'
      }
    }
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}