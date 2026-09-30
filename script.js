// Vibe Check: Secret Scanner
// Runs 100% in the browser. No network requests, no storage, no AI.

"use strict";

const MAX_BYTES = 1024 * 1024; // 1 MB

function mask(value) {
  if (value.length <= 10) return "****";
  return value.slice(0, 4) + "..." + value.slice(-4);
}

function decodeJwtPayload(part) {
  try {
    let b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    return JSON.parse(atob(b64));
  } catch (e) {
    return null;
  }
}

// The only detection rules. Each rule returns the secret value to show (masked),
// or null to skip the match.
const RULES = [
  {
    type: "OpenAI key",
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g,
    show: (m) => mask(m[0]),
    message: "Anyone who sees this code can use your OpenAI account, and you pay the bill. Delete it from the code, move it to an environment variable on your server, and create a new key in your OpenAI dashboard. Treat the old one as stolen."
  },
  {
    type: "AWS access key",
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    show: (m) => mask(m[0]),
    message: "This is half of a login to your AWS account. Combined with the secret key, strangers can run up huge bills or take your data. Deactivate it in AWS right now and create a new one stored in an environment variable."
  },
  {
    type: "AWS secret key",
    regex: /aws[\w-]*(?:secret|key)[\w-]*\s*[:=]\s*["']([A-Za-z0-9\/+=]{40})["']/gi,
    show: (m) => mask(m[1]),
    message: "This is the other half of your AWS login. With it, someone controls your AWS account. Deactivate this key pair in AWS immediately and store the new one in an environment variable."
  },
  {
    type: "Stripe live secret key",
    regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g,
    show: (m) => mask(m[0]),
    message: "This is your real payments key. Someone could issue refunds, read your customers' payment info, and mess with your business. Roll this key in your Stripe dashboard now and keep the new one on your server only."
  },
  {
    type: "Supabase service-role key",
    regex: /eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+/g,
    show: (m) => {
      const payload = decodeJwtPayload(m[1]);
      if (!payload || payload.role !== "service_role") return null; // "anon" keys are public by design
      return mask(m[0]);
    },
    message: "This is the master key to your database. It skips every security rule. Anyone who finds it can read, change, or delete all your users' data. Browser code must only use the public 'anon' key. Rotate this key in Supabase and keep it on the server only."
  },
  {
    type: "GitHub token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    show: (m) => mask(m[0]),
    message: "This gives access to your GitHub account and your code. Revoke it in GitHub settings now and create a new one only if you need it."
  },
  {
    type: "Database address with password",
    regex: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s"'\/]+:)[^@\s"'\/]+@/g,
    show: (m) => m[1] + "****@",
    message: "This is the address and password to your database. Anyone with it can connect directly and do anything. Change the database password and move the address to an environment variable."
  },
  {
    type: "Private key",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    show: (m) => m[0],
    message: "Private keys should never be in code. Someone could use it to pretend to be your server. Replace this key and store it outside your code."
  }
];

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

function scan(text) {
  const findings = [];
  for (const rule of RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      const shown = rule.show(m);
      if (shown !== null) {
        findings.push({ type: rule.type, line: lineOf(text, m.index), value: shown, message: rule.message });
      }
      if (m[0].length === 0) rule.regex.lastIndex++;
    }
  }
  findings.sort((a, b) => a.line - b.line);
  return findings;
}

// ---------- Page code (browser only) ----------
if (typeof document !== "undefined") {
  const input = document.getElementById("code");
  const fileInput = document.getElementById("file");
  const scanBtn = document.getElementById("scan");
  const clearBtn = document.getElementById("clear");
  const results = document.getElementById("results");
  const notice = document.getElementById("notice");

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text; // never innerHTML
    return node;
  }

  function showNotice(text) {
    notice.textContent = text;
    notice.hidden = !text;
  }

  function render(findings) {
    results.replaceChildren();

    const verdict = el("h2", findings.length ? "verdict bad" : "verdict good",
      findings.length
        ? "Found " + findings.length + " leaked secret" + (findings.length === 1 ? "" : "s") + ". Fix " + (findings.length === 1 ? "this" : "these") + " before you deploy anything."
        : "No leaked secrets found. Good. But this only checked for leaked secrets, nothing else.");
    results.append(verdict);

    results.append(el("p", "limits",
      "This scanner only looks for passwords and keys pasted into code. It does not check your login system, your database rules, or anything else. A clean result does not mean your app is safe."));

    if (!findings.length) return;

    const list = el("ol", "findings");
    for (const f of findings) {
      const item = el("li", "finding");
      const head = el("div", "finding-head");
      head.append(el("span", "finding-type", f.type), el("span", "finding-line", "Line " + f.line));
      item.append(head, el("code", "finding-value", f.value), el("p", "finding-msg", f.message));
      list.append(item);
    }
    results.append(list);

    results.append(el("p", "history",
      "Deleting a key from your code is not enough. It stays in your git history and past deployments. Always create a new key and cancel the old one."));

    verdict.setAttribute("tabindex", "-1");
    verdict.focus();
  }

  scanBtn.addEventListener("click", () => {
    const text = input.value;
    if (!text.trim()) {
      showNotice("Paste some code or choose a file first.");
      results.replaceChildren();
      return;
    }
    if (new Blob([text]).size > MAX_BYTES) {
      showNotice("That's more than 1 MB. Scan one file or a smaller chunk at a time.");
      results.replaceChildren();
      return;
    }
    showNotice("");
    render(scan(text));
  });

  clearBtn.addEventListener("click", () => {
    input.value = "";
    fileInput.value = "";
    results.replaceChildren();
    showNotice("");
    input.focus();
  });

  function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      showNotice("That file is more than 1 MB. Scan a smaller file.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      input.value = String(reader.result);
      showNotice("Loaded " + file.name + ". It stayed on your computer. Press Scan.");
      results.replaceChildren();
    };
    reader.onerror = () => showNotice("Couldn't read that file. Try pasting its contents instead.");
    reader.readAsText(file);
  }

  fileInput.addEventListener("change", () => loadFile(fileInput.files[0]));

  input.addEventListener("dragover", (e) => { e.preventDefault(); input.classList.add("dragging"); });
  input.addEventListener("dragleave", () => input.classList.remove("dragging"));
  input.addEventListener("drop", (e) => {
    e.preventDefault();
    input.classList.remove("dragging");
    loadFile(e.dataTransfer.files[0]);
  });
}

if (typeof module !== "undefined") module.exports = { scan };
