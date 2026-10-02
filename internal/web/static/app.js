// Theme: the stored preference is "system" | "light" | "dark". The effective
// light/dark theme is derived from it and, in system mode, tracks the OS
// live. data-theme-pref holds the preference; data-theme holds the effective
// theme the stylesheet keys off.
const themeMedia = window.matchMedia("(prefers-color-scheme: dark)");
function themePref() {
  return document.documentElement.dataset.themePref || "system";
}
function themeIsDark(pref) {
  return pref === "dark" || (pref === "system" && themeMedia.matches);
}

// Boot synchronously (from <head>) so the correct theme is set before first
// paint — no flash of the wrong theme.
(() => {
  const pref = localStorage.getItem("kivraid-theme") || "system";
  const root = document.documentElement;
  root.dataset.themePref = pref;
  root.dataset.theme = themeIsDark(pref) ? "dark" : "light";
})();

// While in system mode, follow the OS as it flips light/dark at runtime.
themeMedia.addEventListener("change", () => {
  if (themePref() === "system") {
    document.documentElement.dataset.theme = themeMedia.matches ? "dark" : "light";
  }
});

function setThemePref(pref) {
  const root = document.documentElement;
  root.classList.add("theme-transition"); // soft cross-fade for this switch
  root.dataset.themePref = pref;
  root.dataset.theme = themeIsDark(pref) ? "dark" : "light";
  localStorage.setItem("kivraid-theme", pref);
  syncThemeControls();
  setTimeout(() => root.classList.remove("theme-transition"), 300);
}

// Reflect the active preference on any theme controls (segmented buttons).
function syncThemeControls() {
  const pref = themePref();
  for (const btn of document.querySelectorAll("[data-theme-set]")) {
    const on = btn.dataset.themeSet === pref;
    btn.classList.toggle("theme-seg-active", on);
    btn.setAttribute("aria-checked", on ? "true" : "false");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Segmented control: each button sets a specific preference.
  for (const btn of document.querySelectorAll("[data-theme-set]")) {
    btn.addEventListener("click", () => setThemePref(btn.dataset.themeSet));
  }
  // Compact control (auth pages): one button cycles system → light → dark.
  const themeOrder = ["system", "light", "dark"];
  for (const btn of document.querySelectorAll("[data-theme-toggle]")) {
    btn.addEventListener("click", () =>
      setThemePref(themeOrder[(themeOrder.indexOf(themePref()) + 1) % themeOrder.length]),
    );
  }
  syncThemeControls();

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

  // Timestamps rendered in UTC by the server, shown in the viewer's zone.
  const thisYear = new Date().getFullYear();
  for (const el of document.querySelectorAll("time[data-local]")) {
    const d = new Date(el.getAttribute("datetime"));
    if (isNaN(d)) continue;
    el.title = el.textContent;
    el.textContent = d.toLocaleString(undefined, {
      year: d.getFullYear() === thisYear ? undefined : "numeric",
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  // Dashboard sign-in chart: group the server's hourly counts into the
  // viewer's local days and draw the last seven as paired bars.
  for (const box of document.querySelectorAll("[data-signin-chart]")) {
    let data;
    try {
      data = JSON.parse(box.dataset.signinChart);
    } catch {
      continue;
    }
    const days = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(d.getDate() - i);
      days.push({ date: d, ok: 0, fail: 0 });
    }
    data.ok.forEach((ok, h) => {
      const t = new Date((data.start + h * 3600) * 1000);
      t.setHours(0, 0, 0, 0);
      const day = days.find((d) => d.date.getTime() === t.getTime());
      if (day) {
        day.ok += ok;
        day.fail += data.fail[h];
      }
    });
    const max = Math.max(1, ...days.map((d) => Math.max(d.ok, d.fail)));
    const el = (tag, cls, text) => {
      const e = document.createElement(tag);
      if (cls) e.className = cls;
      if (text !== undefined) e.textContent = text;
      return e;
    };
    const fmtDay = (d, opts) => d.toLocaleDateString(undefined, opts);

    const legend = el("div", "chart-legend");
    for (const [cls, label] of [["is-ok", "Sign-ins"], ["is-fail", "Failed"]]) {
      const item = el("span");
      const sw = el("span", "chart-swatch " + cls);
      item.append(sw, label);
      legend.append(item);
    }
    const plot = el("div", "chart-plot");
    const maxLine = el("div", "chart-max");
    maxLine.append(el("span", "", String(max)));
    plot.append(maxLine);
    const labels = el("div", "chart-days");
    const table = el("table", "sr-only");
    table.append(el("caption", "", "Sign-ins per day, last 7 days"));
    const head = el("tr");
    head.append(el("th", "", "Day"), el("th", "", "Sign-ins"), el("th", "", "Failed"));
    table.append(head);

    for (const d of days) {
      const name = fmtDay(d.date, { weekday: "short", month: "short", day: "numeric" });
      const col = el("div", "chart-col");
      col.tabIndex = 0;
      col.setAttribute("aria-label", `${name}: ${d.ok} sign-ins, ${d.fail} failed`);
      for (const [cls, v] of [["is-ok", d.ok], ["is-fail", d.fail]]) {
        const bar = el("div", "chart-bar " + cls);
        bar.style.height = v ? Math.max(4, (v / max) * 100) + "%" : "0";
        col.append(bar);
      }
      col.append(el("div", "chart-tip", `${name} · ${d.ok} sign-ins · ${d.fail} failed`));
      plot.append(col);
      labels.append(el("span", "", fmtDay(d.date, { weekday: "narrow" })));
      const row = el("tr");
      row.append(el("td", "", name), el("td", "", String(d.ok)), el("td", "", String(d.fail)));
      table.append(row);
    }
    box.replaceChildren(legend, plot, labels, table);
  }

  // LDAP presets: fill the schema fields for a known directory product.
  for (const btn of document.querySelectorAll("[data-ldap-preset]")) {
    btn.addEventListener("click", () => {
      const preset = JSON.parse(btn.dataset.ldapPreset);
      const form = btn.closest("form");
      for (const [name, value] of Object.entries(preset)) {
        const field = form.elements.namedItem(name);
        if (!field) continue;
        if (field.type === "checkbox") field.checked = value;
        else field.value = value;
      }
    });
  }

  // SMTP: follow the encryption mode with its usual port, unless the admin
  // typed a non-standard one.
  for (const select of document.querySelectorAll("[data-port-field]")) {
    const port = document.getElementById(select.dataset.portField);
    const defaults = [...select.options].map((o) => o.dataset.defaultPort);
    select.addEventListener("change", () => {
      if (port.value === "" || defaults.includes(port.value.trim())) {
        port.value = select.selectedOptions[0].dataset.defaultPort;
      }
    });
  }

  // Image uploads: preview the picked file right away, reject oversized ones
  // before sending, and upload immediately where the field stands alone.
  for (const box of document.querySelectorAll("[data-upload]")) {
    const input = box.querySelector("input[type=file]");
    const preview = box.querySelector("[data-preview]");
    if (!input) continue;
    if (input.hasAttribute("data-autoupload")) {
      box.querySelector("[data-upload-button]")?.setAttribute("hidden", "");
    }
    input.addEventListener("change", () => {
      const file = input.files[0];
      if (!file) return;
      const max = Number(input.dataset.maxBytes || 0);
      if (max && file.size > max) {
        showToast(`That file is too large (max ${Math.round(max / 1048576)} MB).`, "danger");
        input.value = "";
        return;
      }
      if (preview) {
        const reader = new FileReader();
        reader.onload = () => {
          const img = document.createElement("img");
          img.className = preview.dataset.previewClass || "";
          img.alt = "";
          img.src = reader.result;
          preview.replaceChildren(img);
        };
        reader.readAsDataURL(file);
      }
      if (input.hasAttribute("data-autoupload")) input.form.requestSubmit();
    });
  }

  // Filter bars: apply a select as soon as it changes.
  for (const form of document.querySelectorAll("[data-autosubmit]")) {
    for (const field of form.querySelectorAll("select")) {
      field.addEventListener("change", () => form.requestSubmit());
    }
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

    // Integration template: suggest the redirect and post-logout URIs from
    // the launch URL, without overwriting what the admin typed.
    const preset = appForm.querySelector("[data-preset]");
    const launch = appForm.querySelector("#launch_url");
    const redirect = appForm.querySelector("#redirect_uris");
    const postLogout = appForm.querySelector("#post_logout_uris");
    if (preset && launch && redirect && postLogout) {
      const suggested = new WeakMap();
      const fill = (field, value) => {
        if (field.value.trim() === "" || field.value === suggested.get(field)) {
          field.value = value;
          suggested.set(field, value);
        }
      };
      const suggest = () => {
        let origin = "";
        try {
          origin = new URL(launch.value.trim()).origin;
        } catch {
          return;
        }
        const path = preset.selectedOptions[0]?.dataset.redirectPath || "";
        if (path) fill(redirect, origin + path);
        fill(postLogout, origin);
      };
      preset.addEventListener("change", suggest);
      launch.addEventListener("input", suggest);
    }
  }

  // Integration snippets: show the one matching the selected template.
  for (const box of document.querySelectorAll("[data-snippets]")) {
    const select = box.querySelector("[data-snippet-select]");
    const show = () => {
      for (const pane of box.querySelectorAll("[data-snippet]")) {
        pane.hidden = pane.dataset.snippet !== select.value;
      }
    };
    select.addEventListener("change", show);
    show();
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

  // Two-factor challenge: switch the single code field between
  // authenticator codes (numeric keyboard) and recovery codes.
  const mfaToggle = document.querySelector("[data-mfa-recovery-toggle]");
  if (mfaToggle) {
    const input = document.getElementById("code");
    const label = document.querySelector('label[for="code"]');
    let recovery = false;
    mfaToggle.addEventListener("click", () => {
      recovery = !recovery;
      input.value = "";
      input.inputMode = recovery ? "text" : "numeric";
      input.placeholder = recovery ? "xxxx-xxxx" : "000000";
      input.autocomplete = recovery ? "off" : "one-time-code";
      label.textContent = recovery ? "Recovery code" : "Authentication code";
      mfaToggle.textContent = recovery
        ? "Use an authenticator code instead"
        : "Lost your device? Use a recovery code";
      input.focus();
    });
  }

  // Generate a strong random password into a field and reveal it.
  for (const btn of document.querySelectorAll("[data-generate-password]")) {
    btn.addEventListener("click", () => {
      const field = document.getElementById(btn.dataset.generatePassword);
      const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
      const bytes = crypto.getRandomValues(new Uint32Array(16));
      field.value = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
      if (field.type === "password") {
        field.parentElement.querySelector("[data-secret-toggle]")?.click();
      }
    });
  }

  // Copy the current value of a form field.
  for (const btn of document.querySelectorAll("[data-copy-field]")) {
    btn.addEventListener("click", async () => {
      const field = document.getElementById(btn.dataset.copyField);
      if (!field.value) return;
      await navigator.clipboard.writeText(field.value);
      const original = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(() => (btn.textContent = original), 1500);
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
