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

  // Tag-style multi-select with datalist autocomplete: picking an option
  // turns it into a removable chip carrying a hidden form input.
  for (const box of document.querySelectorAll("[data-tagselect]")) {
    const input = box.querySelector("[data-tag-input]");
    const tags = box.querySelector("[data-tags]");
    const datalist = document.getElementById(input.getAttribute("list"));
    const fieldName = input.dataset.tagName;

    const addTag = () => {
      const option = [...datalist.options].find(
        (o) => o.value.toLowerCase() === input.value.trim().toLowerCase(),
      );
      if (!option) return;
      const chip = document.createElement("span");
      chip.className = "chip flex items-center gap-1.5";
      chip.dataset.tag = "";
      chip.dataset.name = option.value;
      chip.append(option.value);
      const hidden = document.createElement("input");
      hidden.type = "hidden";
      hidden.name = fieldName;
      hidden.value = option.dataset.id;
      chip.append(hidden);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.dataset.tagRemove = "";
      remove.className = "cursor-pointer text-faint hover:text-fg";
      remove.setAttribute("aria-label", "Remove " + option.value);
      remove.append("×");
      chip.append(remove);
      tags.append(chip);
      option.remove();
      input.value = "";
    };

    input.addEventListener("change", addTag);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault(); // don't submit the surrounding form
        addTag();
      }
    });
    box.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-tag-remove]");
      if (!btn) return;
      const chip = btn.closest("[data-tag]");
      const option = document.createElement("option");
      option.value = chip.dataset.name;
      option.dataset.id = chip.querySelector("input[type=hidden]").value;
      datalist.append(option);
      chip.remove();
    });
  }

  // New-application wizard: show the OIDC or forward-auth section
  // depending on the selected integration kind.
  const appForm = document.querySelector("[data-appform]");
  if (appForm) {
    const oidc = appForm.querySelector("[data-kind-oidc]");
    const proxy = appForm.querySelector("[data-kind-proxy]");
    const sync = () => {
      const kind =
        appForm.querySelector("[data-kind]:checked")?.value || "oidc";
      oidc.classList.toggle("hidden", kind !== "oidc");
      proxy.classList.toggle("hidden", kind !== "proxy");
    };
    for (const radio of appForm.querySelectorAll("[data-kind]")) {
      radio.addEventListener("change", sync);
    }
    sync();
  }

  // Reveal/hide toggle for masked secrets (eye ↔ eye-off).
  for (const btn of document.querySelectorAll("[data-secret-toggle]")) {
    btn.addEventListener("click", () => {
      const field = btn.parentElement.querySelector("[data-secret]");
      const shown = field.type === "text";
      field.type = shown ? "password" : "text";
      btn.querySelector("[data-eye]").classList.toggle("hidden", !shown);
      btn.querySelector("[data-eye-off]").classList.toggle("hidden", shown);
      btn.setAttribute("aria-label", shown ? "Show secret" : "Hide secret");
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
