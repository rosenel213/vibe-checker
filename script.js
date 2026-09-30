// Vibe Check: Secret Scanner
// Runs 100% in the browser. No network requests, no storage, no AI.

"use strict";

const MAX_BYTES = 1024 * 1024; // 1 MB per paste or per file

// ---------- Helpers ----------

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

// Passwords that are clearly template text, not real passwords.
function isPlaceholderPassword(pw) {
  if (/[\[\]<>{}$]/.test(pw)) return true; // [YOUR-PASSWORD], <password>, ${DB_PASS}
  return /^(?:your[-_]?password|password|pass|changeme|secret|x+|\*+)$/i.test(pw);
}

// ---------- Detection rules (the only ones) ----------

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
    regex: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s"'\/]+:)([^@\s"'\/]+)@/g,
    show: (m) => (isPlaceholderPassword(m[2]) ? null : m[1] + "****@"),
    message: "This is the address and password to your database. Anyone with it can connect directly and do anything. Change the database password and move the address to an environment variable."
  },
  {
    type: "Private key",
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    show: (m) => m[0],
    message: "Private keys should never be in code. Someone could use it to pretend to be your server. Replace this key and store it outside your code."
  }
];

const ENV_MESSAGE = "This is in an environment file, which is the right place for secrets, but only if this file never leaves your computer or server. Make sure .env files are listed in your .gitignore. If this file was ever pushed to GitHub or shared, treat the key as stolen and replace it.";

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

function isEnvFile(path) {
  const name = path.split("/").pop();
  return /^\.env(?:\.|$)/.test(name) && !/\.(?:example|sample|template)$/.test(name);
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

// ---------- Folder scanning ----------

const SKIP_FOLDERS = new Set(["node_modules", ".git", ".next", "dist", "build", "out", "coverage", ".vercel", ".turbo", ".cache"]);
const SKIP_FILES = new Set(["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]);
const SKIP_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "avif",
  "mp3", "mp4", "wav", "mov", "webm", "ogg",
  "woff", "woff2", "ttf", "otf", "eot",
  "zip", "gz", "tar", "rar", "7z", "pdf", "exe", "dll", "so", "wasm", "map"
]);

// Returns a reason string if the file should be skipped, or null to scan it.
function skipReason(path, size) {
  const parts = path.split("/");
  for (const part of parts.slice(0, -1)) {
    if (SKIP_FOLDERS.has(part)) return "folder:" + part;
  }
  const name = parts[parts.length - 1];
  if (SKIP_FILES.has(name)) return "Lock files (list of downloaded libraries)";
  const ext = name.includes(".") ? name.split(".").pop().toLowerCase() : "";
  if (SKIP_EXTENSIONS.has(ext)) return "Images, media, fonts and other non-code files";
  if (size > MAX_BYTES) return "Files larger than 1 MB";
  return null;
}

// Removes the top folder name so paths read like ".env" or "src/api/chat.js".
function displayPath(relativePath) {
  const parts = relativePath.split("/");
  return parts.length > 1 ? parts.slice(1).join("/") : relativePath;
}

// entries: [{ path, text }] for files that were read. Pure function, easy to test.
function scanEntries(entries) {
  const results = [];
  for (const entry of entries) {
    if (entry.text.includes("\u0000")) continue; // binary file
    const findings = scan(entry.text);
    if (isEnvFile(entry.path)) {
      for (const f of findings) { f.message = ENV_MESSAGE; f.inEnv = true; }
    }
    if (findings.length) results.push({ path: entry.path, findings });
  }
  results.sort((a, b) => a.path.localeCompare(b.path));
  return results;
}

// ---------- Page code (browser only) ----------

if (typeof document !== "undefined") {
  const input = document.getElementById("code");
  const fileInput = document.getElementById("file");
  const folderInput = document.getElementById("folder");
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

  function plural(n, word) {
    return n + " " + word + (n === 1 ? "" : "s");
  }

  function findingCard(f) {
    const item = el("li", f.inEnv ? "finding env" : "finding");
    const head = el("div", "finding-head");
    head.append(el("span", "finding-type", f.type), el("span", "finding-line", "Line " + f.line));
    item.append(head, el("code", "finding-value", f.value), el("p", "finding-msg", f.message));
    return item;
  }

  // groups: [{ path, findings }]; summary: { checked, skipped: Map(reason -> [paths]) } or null for paste mode
  function render(groups, summary) {
    results.replaceChildren();
    const all = groups.flatMap((g) => g.findings);
    const inEnv = all.filter((f) => f.inEnv).length;
    const inCode = all.length - inEnv;

    let verdictText;
    if (!all.length) {
      verdictText = "No leaked secrets found. Good. But this only checked for leaked secrets, nothing else.";
    } else if (!inEnv) {
      verdictText = "Found " + plural(all.length, "leaked secret") + ". Fix " + (all.length === 1 ? "this" : "these") + " before you deploy anything.";
    } else if (!inCode) {
      verdictText = "Found " + plural(inEnv, "secret") + " in .env files. That's the right place, but only if those files are never shared or committed.";
    } else {
      verdictText = "Found " + plural(all.length, "secret") + ". " + inCode + " " + (inCode === 1 ? "is" : "are") + " sitting in your code, where anyone can find " + (inCode === 1 ? "it" : "them") + ". Fix those first.";
    }
    const verdict = el("h2", all.length ? "verdict bad" : "verdict good", verdictText);
    results.append(verdict);

    results.append(el("p", "limits",
      "This scanner only looks for passwords and keys. It does not check your login system, your database rules, or anything else. A clean result does not mean your app is safe."));

    if (summary) {
      let skippedCount = 0;
      for (const paths of summary.skipped.values()) skippedCount += paths.length;
      results.append(el("p", "coverage", "Checked " + plural(summary.checked, "file") + ". Skipped " + plural(skippedCount, "file") + "."));
      if (skippedCount) {
        const details = el("details", "skipped");
        details.append(el("summary", null, "What was skipped, and why"));
        const list = el("ul");
        for (const [reason, paths] of summary.skipped) {
          const label = reason.startsWith("folder:")
            ? "The " + reason.slice(7) + " folder (downloaded or generated files, not your own code)"
            : reason;
          list.append(el("li", null, label + ": " + plural(paths.length, "file")));
        }
        details.append(list);
        results.append(details);
      }
    }

    for (const group of groups) {
      if (summary) results.append(el("h3", "file-name", group.path));
      const list = el("ol", "findings");
      for (const f of group.findings) list.append(findingCard(f));
      results.append(list);
    }

    if (inCode) {
      results.append(el("p", "history",
        "Deleting a key from your code is not enough. It stays in your git history and past deployments. Always create a new key and cancel the old one."));
    }

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
    const findings = scan(text);
    render(findings.length ? [{ path: "Pasted code", findings }] : [], null);
  });

  clearBtn.addEventListener("click", () => {
    input.value = "";
    fileInput.value = "";
    folderInput.value = "";
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

  folderInput.addEventListener("change", async () => {
    const files = Array.from(folderInput.files);
    if (!files.length) return;
    input.value = "";
    results.replaceChildren();

    const skipped = new Map();
    const toRead = [];
    for (const file of files) {
      const path = displayPath(file.webkitRelativePath || file.name);
      const reason = skipReason(path, file.size);
      if (reason) {
        if (!skipped.has(reason)) skipped.set(reason, []);
        skipped.get(reason).push(path);
      } else {
        toRead.push({ file, path });
      }
    }

    showNotice("Checking " + plural(toRead.length, "file") + " on your computer...");
    const entries = [];
    const unreadable = [];
    for (const { file, path } of toRead) {
      try {
        entries.push({ path, text: await file.text() });
      } catch (e) {
        unreadable.push(path);
      }
    }
    if (unreadable.length) skipped.set("Files the browser couldn't read", unreadable);

    const binary = entries.filter((e) => e.text.includes("\u0000")).map((e) => e.path);
    if (binary.length) skipped.set("Non-text files", binary);

    showNotice("");
    render(scanEntries(entries), { checked: entries.length - binary.length, skipped });
    folderInput.value = "";
  });
}

if (typeof module !== "undefined") module.exports = { scan, scanEntries, skipReason, displayPath };
