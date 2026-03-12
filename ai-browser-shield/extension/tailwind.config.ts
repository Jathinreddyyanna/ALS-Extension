/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{ts,tsx,html}'],
  theme: {
    extend: {
      colors: {
        shield: {
          navy: '#0F2044',
          blue: '#1D4ED8',
          danger: '#991B1B',
          warn: '#B45309',
          safe: '#166534',
        }
      }
    }
  },
  plugins: [],
}
