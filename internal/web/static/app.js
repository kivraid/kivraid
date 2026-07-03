// Theme boot: runs synchronously from <head> so the correct theme is set
// before first paint (no flash of the wrong theme).
(() => {
  const stored = localStorage.getItem("kivraid-theme");
  const dark = stored
    ? stored === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "dark" : "light";
})();

document.addEventListener("DOMContentLoaded", () => {
  for (const btn of document.querySelectorAll("[data-theme-toggle]")) {
    btn.addEventListener("click", () => {
      const next =
        document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("kivraid-theme", next);
    });
  }

  // Click-to-insert example values (chips next to filter fields).
  for (const btn of document.querySelectorAll("[data-fill]")) {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.fill);
      if (!input) return;
      input.value = btn.dataset.value;
      input.focus();
    });
  }

  // Copy-to-clipboard for credentials and endpoint URLs.
  for (const btn of document.querySelectorAll("[data-copy]")) {
    btn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(btn.dataset.copy);
      const original = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => (btn.textContent = original), 1500);
    });
  }
});

// Confirmation guard for destructive forms (CSP forbids inline handlers).
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset && e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});

// Dropdown menus: a [data-menu-button] toggles its [data-menu] container;
// clicking anywhere else (or pressing Escape) closes every open menu.
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-menu-button]");
  for (const menu of document.querySelectorAll("[data-menu]")) {
    if (btn && menu.contains(btn)) menu.classList.toggle("menu-open");
    else if (!e.target.closest(".menu-panel") || !menu.contains(e.target)) {
      menu.classList.remove("menu-open");
    }
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    for (const menu of document.querySelectorAll("[data-menu]")) {
      menu.classList.remove("menu-open");
    }
  }
});
