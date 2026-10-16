module.exports = {
  content: [
    "./src/**/*.py",
    "./src/webapp/templates/**/*.html",
    "./src/webapp/static/*.js"
  ],
  theme: {
    extend: {
      colors: {
        whatsapp: {
          light: "#dcf8c6",
          main: "#25D366",
          dark: "#128C7E"
        },
        primary: "#3b82f6"
      }
    }
  },
  plugins: [require("@tailwindcss/forms")]
};
