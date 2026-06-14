/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './management/templates/**/*.html',
    './management/static/**/*.js',
  ],
  theme: {
    extend: {
      colors: {
        'slate-950': '#0f172a',
        'slate-800': '#1e293b',
        'slate-700': '#334155',
        'sky-500':   '#0ea5e9',
      }
    }
  },
  plugins: [],
}
