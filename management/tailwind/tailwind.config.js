/** Build:  cd management/tailwind && npx tailwindcss@3 -c tailwind.config.js \
 *            -i input.css -o ../static/tailwind.css --minify
 *  Produces the purged, production Tailwind CSS for the Management UI
 *  (replaces the 407KB Play/runtime build). */
module.exports = {
  darkMode: 'class',
  content: ['../templates/**/*.html'],
  theme: { extend: { colors: {
    'slate-950': '#0b0f19', 'slate-800': '#0f1524',
    'slate-700': '#1e293b', 'sky-500': '#0ea5e9',
  } } },
}
