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
      const root = document.documentElement;
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      // Soft cross-fade, enabled only for the duration of the switch.
      root.classList.add("theme-transition");
      root.dataset.theme = next;
      localStorage.setItem("kivraid-theme", next);
      setTimeout(() => root.classList.remove("theme-transition"), 300);
    });
  }

  // Instant client-side filtering of lists. An [data-list-filter] input
  // hides sibling-scoped [data-list-item] rows that do not match.
  for (const input of document.querySelectorAll("[data-list-filter]")) {
    const list = document.querySelector(input.dataset.listFilter);
    if (!list) continue;
    const items = [...list.querySelectorAll("[data-list-item]")];
    const empty = document.querySelector(input.dataset.listEmpty);
    input.addEventListener("input", () => {
      const q = input.value.trim().toLowerCase();
      let shown = 0;
      for (const item of items) {
        const match = item.textContent.toLowerCase().includes(q);
        item.hidden = !match;
        if (match) shown++;
      }
      if (empty) empty.hidden = shown !== 0;
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

// Transient toast notifications (bottom-center), driven by [data-flash]
// elements the server renders and by client-side actions.
function showToast(message, variant) {
  let region = document.getElementById("toast-region");
  if (!region) {
    region = document.createElement("div");
    region.id = "toast-region";
    region.className = "toast-region";
    document.body.append(region);
  }
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.setAttribute("role", "status");
  const dot = document.createElement("span");
  dot.className = "toast-dot";
  dot.style.background =
    variant === "danger" ? "var(--danger)" : "var(--accent)";
  toast.append(dot, document.createTextNode(message));
  region.append(toast);
  setTimeout(() => {
    toast.dataset.leaving = "";
    toast.addEventListener("animationend", () => toast.remove());
  }, 3200);
}

document.addEventListener("DOMContentLoaded", () => {
  for (const el of document.querySelectorAll("[data-flash]")) {
    showToast(el.dataset.flash, el.dataset.variant);
    el.remove();
  }
});

// Confirmation modal for destructive forms: a form carrying data-confirm
// opens a proper dialog instead of the native confirm() popup. On confirm
// the original form is submitted directly (which does not re-fire submit,
// so the guard is not re-entered). CSP forbids inline handlers, hence the
// delegated listener.
const confirmState = { form: null };

function ensureConfirmDialog() {
  let dlg = document.getElementById("confirm-dialog");
  if (dlg) return dlg;
  dlg = document.createElement("dialog");
  dlg.id = "confirm-dialog";
  dlg.className = "modal";
  dlg.innerHTML = `
    <h2 data-confirm-title class="text-base font-semibold tracking-tight"></h2>
    <p data-confirm-body class="mt-2 text-sm text-muted"></p>
    <div class="mt-6 flex justify-end gap-3">
      <button type="button" data-confirm-cancel class="btn-secondary">Cancel</button>
      <button type="button" data-confirm-ok class="btn-primary"></button>
    </div>`;
  document.body.append(dlg);

  const close = () => dlg.close();
  dlg.querySelector("[data-confirm-cancel]").addEventListener("click", close);
  dlg.addEventListener("cancel", (e) => {
    // Esc: let the dialog close without submitting.
    e.preventDefault();
    close();
  });
  // Click on the backdrop (outside the content) cancels.
  dlg.addEventListener("click", (e) => {
    if (e.target === dlg) close();
  });
  dlg.querySelector("[data-confirm-ok]").addEventListener("click", () => {
    const form = confirmState.form;
    dlg.close();
    if (form) form.submit();
  });
  return dlg;
}

document.addEventListener("submit", (e) => {
  const form = e.target;
  if (!form.dataset || !form.dataset.confirm) return;
  e.preventDefault();
  confirmState.form = form;
  const dlg = ensureConfirmDialog();
  const danger = form.dataset.confirmVariant === "danger";
  dlg.querySelector("[data-confirm-title]").textContent =
    form.dataset.confirmTitle || "Please confirm";
  dlg.querySelector("[data-confirm-body]").textContent = form.dataset.confirm;
  const ok = dlg.querySelector("[data-confirm-ok]");
  ok.textContent = form.dataset.confirmLabel || "Confirm";
  ok.className = danger ? "btn-danger" : "btn-primary";
  dlg.showModal();
  dlg.querySelector("[data-confirm-cancel]").focus();
});

// Loading state: on a real submit (not one a confirm dialog intercepted),
// disable the triggering button and show a spinner so slow actions (LDAP
// test/sync, saves) feel responsive and double-submits are prevented.
document.addEventListener("submit", (e) => {
  if (e.defaultPrevented) return;
  const btn = e.submitter;
  if (!btn || btn.dataset.noSpinner !== undefined) return;
  const label = btn.textContent.trim();
  btn.disabled = true;
  btn.dataset.width = btn.offsetWidth; // avoid a width jump
  btn.style.minWidth = btn.offsetWidth + "px";
  btn.innerHTML = `<span class="spinner"></span><span class="sr-only">${label}</span>`;
});

// Dropdown menus: a [data-menu-button] toggles its [data-menu] container;
// clicking anywhere else (or pressing Escape) closes every open menu.
function syncMenuAria(menu) {
  const btn = menu.querySelector("[data-menu-button]");
  if (btn) btn.setAttribute("aria-expanded", menu.classList.contains("menu-open"));
}
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-menu-button]");
  for (const menu of document.querySelectorAll("[data-menu]")) {
    if (btn && menu.contains(btn)) menu.classList.toggle("menu-open");
    else if (!e.target.closest(".menu-panel") || !menu.contains(e.target)) {
      menu.classList.remove("menu-open");
    }
    syncMenuAria(menu);
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    for (const menu of document.querySelectorAll("[data-menu]")) {
      menu.classList.remove("menu-open");
      syncMenuAria(menu);
    }
  }
});

// ---- WebAuthn / passkeys ----
// The server speaks base64url over JSON; the browser API speaks
// ArrayBuffers. These helpers translate between the two.
function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  let bin = "";
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function csrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || "";
}
async function waPost(url, body) {
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken(),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
// A cancelled or timed-out ceremony is a user choice, not an error to shout.
function isCeremonyCancel(err) {
  return (
    err &&
    (err.name === "NotAllowedError" ||
      err.name === "AbortError" ||
      err.name === "InvalidStateError")
  );
}

async function registerPasskey(name) {
  const begin = await waPost("/profile/passkeys/begin");
  if (!begin.ok) throw new Error("Could not start registration.");
  const opts = (await begin.json()).publicKey;
  opts.challenge = b64urlToBuf(opts.challenge);
  opts.user.id = b64urlToBuf(opts.user.id);
  for (const c of opts.excludeCredentials || []) c.id = b64urlToBuf(c.id);
  const cred = await navigator.credentials.create({ publicKey: opts });
  const finish = await waPost(
    "/profile/passkeys/finish?name=" + encodeURIComponent(name),
    {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
      },
    },
  );
  if (!finish.ok) throw new Error("The passkey could not be registered.");
}

async function loginWithPasskey(next) {
  const begin = await waPost("/login/passkey/begin");
  if (!begin.ok) throw new Error("Could not start passkey sign-in.");
  const opts = (await begin.json()).publicKey;
  opts.challenge = b64urlToBuf(opts.challenge);
  for (const c of opts.allowCredentials || []) c.id = b64urlToBuf(c.id);
  const cred = await navigator.credentials.get({ publicKey: opts });
  const finish = await waPost(
    "/login/passkey/finish?next=" + encodeURIComponent(next || ""),
    {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle
          ? bufToB64url(cred.response.userHandle)
          : null,
      },
    },
  );
  if (!finish.ok) throw new Error("That passkey wasn't recognized.");
  const data = await finish.json();
  window.location.href = data.next || "/";
}

document.addEventListener("DOMContentLoaded", () => {
  const supported =
    typeof window.PublicKeyCredential !== "undefined" &&
    !!navigator.credentials;

  // Login page: reveal the passkey option only when the browser can use it.
  const loginBox = document.querySelector("[data-passkey-login]");
  const loginBtn = document.querySelector("[data-passkey-login-btn]");
  if (loginBox && loginBtn && supported) {
    loginBox.hidden = false;
    const err = document.querySelector("[data-passkey-error]");
    loginBtn.addEventListener("click", async () => {
      if (err) err.hidden = true;
      loginBtn.disabled = true;
      try {
        await loginWithPasskey(loginBtn.dataset.next);
      } catch (e) {
        if (!isCeremonyCancel(e) && err) {
          err.textContent = e.message || "Passkey sign-in failed.";
          err.hidden = false;
        }
        loginBtn.disabled = false;
      }
    });
  }

  // Profile page: register a new passkey.
  const addBtn = document.querySelector("[data-passkey-add]");
  if (addBtn && supported) {
    const nameInput = document.querySelector("[data-passkey-name]");
    const err = document.querySelector("[data-passkeys] [data-passkey-error]");
    addBtn.addEventListener("click", async () => {
      if (err) err.hidden = true;
      const name = (nameInput?.value || "").trim() || "Passkey";
      addBtn.disabled = true;
      try {
        await registerPasskey(name);
        showToast("Passkey added.");
        setTimeout(() => window.location.reload(), 600);
      } catch (e) {
        if (!isCeremonyCancel(e) && err) {
          err.textContent = e.message || "Could not add passkey.";
          err.hidden = false;
        }
        addBtn.disabled = false;
      }
    });
  } else if (addBtn) {
    addBtn.disabled = true;
    addBtn.title = "This browser does not support passkeys.";
  }
});
