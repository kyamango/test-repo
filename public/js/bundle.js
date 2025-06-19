(() => {
  // <stdin>
  (function() {
    const toggleButtons = document.querySelectorAll(".toggle-button");
    function hideAllExcept(targetElement) {
      document.querySelectorAll(".hidden").forEach((element) => {
        if (element !== targetElement) {
          element.classList.add("close");
          element.classList.remove("open");
        }
      });
    }
    function toggleElement(targetElement) {
      const isHidden = targetElement.classList.contains("close");
      hideAllExcept(targetElement);
      targetElement.classList.toggle("close", !isHidden);
      targetElement.classList.toggle("open", isHidden);
    }
    toggleButtons.forEach((button) => {
      button.addEventListener("click", function() {
        const targetIds = this.getAttribute("data-target").split(" ");
        targetIds.forEach((targetId) => {
          const targetElement = document.getElementById(targetId);
          if (targetElement) {
            toggleElement(targetElement);
          }
        });
      });
    });
    document.addEventListener("click", function(event) {
      const targetElements = Array.from(document.querySelectorAll(".open"));
      const clickedOutsideAllTargets = targetElements.every((element) => {
        return !element.contains(event.target) && !event.target.closest(".toggle-button");
      });
      if (clickedOutsideAllTargets) {
        targetElements.forEach((element) => {
          element.classList.remove("open");
          element.classList.add("close");
        });
      }
    });
  })();
  document.addEventListener("DOMContentLoaded", function() {
    const toggle = document.getElementById("darkModeToggle");
    const html = document.documentElement;
    const sunIcon = document.getElementById("sunIcon");
    const moonIcon = document.getElementById("moonIcon");
    const darkStylesheet = document.getElementById("dark-mode-theme");
    function enableDarkMode() {
      html.classList.add("dark");
      if (darkStylesheet) {
        darkStylesheet.media = "all";
      }
      if (sunIcon && moonIcon) {
        sunIcon.classList.add("hidden");
        moonIcon.classList.remove("hidden");
      }
      localStorage.setItem("theme", "dark");
    }
    function disableDarkMode() {
      html.classList.remove("dark");
      if (darkStylesheet) {
        darkStylesheet.media = "not all";
      }
      if (sunIcon && moonIcon) {
        sunIcon.classList.remove("hidden");
        moonIcon.classList.add("hidden");
      }
      localStorage.setItem("theme", "light");
    }
    const savedTheme = localStorage.getItem("theme");
    const prefersDarkScheme = window.matchMedia("(prefers-color-scheme: dark)");
    if (savedTheme === "dark" || !savedTheme && prefersDarkScheme.matches) {
      enableDarkMode();
    } else {
      disableDarkMode();
    }
    if (toggle) {
      toggle.addEventListener("click", () => {
        if (html.classList.contains("dark")) {
          disableDarkMode();
        } else {
          enableDarkMode();
        }
      });
    }
  });
})();
