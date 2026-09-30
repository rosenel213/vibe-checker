// Vibe Check: Folder rules
// Which files in a project folder get skipped, and how file paths are shown.
// Runs 100% in the browser. No network requests, no storage, no AI.

(function (VC) {
  "use strict";
  const { MAX_BYTES } = VC;

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

  VC.skipReason = skipReason;
  VC.displayPath = displayPath;
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
