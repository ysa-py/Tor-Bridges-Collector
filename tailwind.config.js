/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        tor: {
          dark: '#0e131f',
          card: '#161d2f',
          border: '#242e47',
          purple: '#7d5fff',
          green: '#00d26a',
          cyan: '#00e5ff',
          amber: '#ffb300',
          rose: '#ff4757',
        }
      }
    },
  },
  plugins: [],
}
