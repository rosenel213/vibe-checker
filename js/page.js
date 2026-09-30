// Vibe Check: Page
// Connects the buttons and results on the page to the checks. Loaded last.
// Runs 100% in the browser. No network requests, no storage, no AI.

(function (VC) {
  "use strict";
  const { MAX_BYTES, scan, checkRls, scanEntries, skipReason, displayPath, RLS_UNCHECKED } = VC;

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

  let seenMessages = new Set();

  function findingCard(f) {
    const item = el("li", f.inEnv ? "finding env" : "finding");
    const head = el("div", "finding-head");
    head.append(el("span", "finding-type", f.type));
    if (f.line) head.append(el("span", "finding-line", "Line " + f.line));
    item.append(head);
    if (f.value) item.append(el("code", "finding-value", f.value));
    if (seenMessages.has(f.message)) {
      item.append(el("p", "finding-msg repeat", "Same problem as " + f.type.toLowerCase() + " above. Same fix."));
    } else {
      seenMessages.add(f.message);
      item.append(el("p", "finding-msg", f.message));
    }
    return item;
  }

  // groups: [{ path, findings }]; summary: { checked, skipped: Map(reason -> [paths]) } or null for paste mode
  function render(groups, summary, note) {
    results.replaceChildren();
    seenMessages = new Set();
    const all = groups.flatMap((g) => g.findings);
    const setup = all.filter((f) => f.setup).length;
    const exposed = all.filter((f) => f.exposed).length;
    const inEnv = all.filter((f) => f.inEnv).length;
    const tablesOpen = all.filter((f) => f.setupDb).length;
    const inCode = all.length - inEnv - setup - exposed - tablesOpen;

    let verdictText;
    if (!all.length) {
      verdictText = note === RLS_UNCHECKED
        ? "No problems found in what we could check. But we couldn't check your database tables. See below."
        : "No problems found. Good. But this only checked for the specific problems listed below, nothing else.";
    } else if (setup || exposed || tablesOpen) {
      const parts = [];
      if (inCode) parts.push(plural(inCode, "secret") + " sitting in your code");
      if (exposed) parts.push(plural(exposed, "secret") + " marked public");
      if (inEnv) parts.push(plural(inEnv, "secret") + " in .env files");
      if (setup) parts.push(setup + " .env " + (setup === 1 ? "file" : "files") + " not protected from GitHub");
      if (tablesOpen) parts.push(plural(tablesOpen, "database table") + " open to anyone");
      verdictText = "Found " + plural(all.length, "problem") + ": " + parts.join(", ") + ". Fix these before you push or deploy anything.";
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
      "This scanner looks for leaked passwords and keys, secrets marked public, .env files not protected by .gitignore, and Supabase tables without Row Level Security. It does not check your login system, the details of your database rules, or anything else. A clean result does not mean your app is safe."));

    if (note) results.append(el("p", note === RLS_UNCHECKED ? "db-note warn" : "db-note", note));

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
    const findings = scan(text).concat(checkRls([{ path: "Pasted code", text: text }], { notes: false }).problems.map((p) => p.finding));
    findings.sort((a, b) => a.line - b.line);
    render(findings.length ? [{ path: "Pasted code", findings }] : [], null, null);
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
    const groups = scanEntries(entries);
    render(groups, { checked: entries.length - binary.length, skipped }, groups.note);
    folderInput.value = "";
  });
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
