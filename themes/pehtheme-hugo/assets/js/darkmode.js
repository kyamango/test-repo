document.addEventListener('DOMContentLoaded', function() {
  const toggle = document.getElementById('darkModeToggle');
  const html = document.documentElement;
  const sunIcon = document.getElementById('sunIcon');
  const moonIcon = document.getElementById('moonIcon');
  const darkStylesheet = document.getElementById('dark-mode-theme');

  function enableDarkMode() {
    html.classList.add('dark');
    if (darkStylesheet) {
      darkStylesheet.media = 'all';
    }
    if (sunIcon && moonIcon) {
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
    }
    localStorage.setItem('theme', 'dark');
  }

  function disableDarkMode() {
    html.classList.remove('dark');
    if (darkStylesheet) {
      darkStylesheet.media = 'not all';
    }
    if (sunIcon && moonIcon) {
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
    }
    localStorage.setItem('theme', 'light');
  }

  const savedTheme = localStorage.getItem('theme');
  const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
  
  if (savedTheme === 'dark' || (!savedTheme && prefersDarkScheme.matches)) {
    enableDarkMode();
  } else {
    disableDarkMode();
  }

  if (toggle) {
    toggle.addEventListener('click', () => {
      if (html.classList.contains('dark')) {
        disableDarkMode();
      } else {
        enableDarkMode();
      }
    });
  }
});