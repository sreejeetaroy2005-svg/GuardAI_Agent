// tailwind.config.cjs
module.exports = {
  darkMode: 'class', // enable class based dark mode
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: 'hsl(210, 30%, 30%)',
        secondary: 'hsl(210, 20%, 45%)',
        accent: 'hsl(210, 70%, 55%)',
        success: 'hsl(140, 70%, 45%)',
        danger: 'hsl(0, 70%, 45%)',
        warning: 'hsl(40, 70%, 45%)',
      },
    },
  },
  plugins: [],
};
