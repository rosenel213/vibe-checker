// Vibe Check: Check: .env protected by .gitignore
// Reads .gitignore files and flags .env files that could be pushed to GitHub.
// Runs 100% in the browser. No network requests, no storage, no AI.

(function (VC) {
  "use strict";
  const { isEnvFile } = VC;

  // ---------- Check: .env files protected by .gitignore ----------

  function globToRegex(glob) {
    let re = "";
    for (let i = 0; i < glob.length; i++) {
      const c = glob[i];
      if (c === "*") {
        if (glob[i + 1] === "*") {
          if (glob[i + 2] === "/") { re += "(?:.*/)?"; i += 2; }
          else { re += ".*"; i += 1; }
        } else {
          re += "[^/]*";
        }
      } else if (c === "?") {
        re += "[^/]";
      } else if ("\\^$+.()|{}[]".includes(c)) {
        re += "\\" + c;
      } else {
        re += c;
      }
    }
    return re;
  }

  // Turns one .gitignore file into a list of rules. baseDir is its folder ("" for the top).
  function parseGitignore(text, baseDir) {
    const rules = [];
    for (let line of text.split(/\r?\n/)) {
      line = line.replace(/\s+$/, "");
      if (!line || line.startsWith("#")) continue;
      let negate = false;
      if (line.startsWith("!")) { negate = true; line = line.slice(1); }
      else if (line.startsWith("\\")) { line = line.slice(1); }
      let dirOnly = false;
      if (line.endsWith("/")) { dirOnly = true; line = line.slice(0, -1); }
      const anchored = line.includes("/");
      if (line.startsWith("/")) line = line.slice(1);
      if (!line) continue;
      const body = globToRegex(line);
      const regex = new RegExp(anchored ? "^" + body + "$" : "^(?:.*/)?" + body + "$");
      rules.push({ regex, negate, dirOnly, baseDir });
    }
    return rules;
  }

  function dirOf(path) {
    const i = path.lastIndexOf("/");
    return i === -1 ? "" : path.slice(0, i);
  }

  // Decides if one path (file or folder) is ignored, using every .gitignore above it.
  function matchesIgnore(path, isDir, gitignores) {
    let ignored = false;
    for (const g of gitignores) {
      const prefix = g.dir ? g.dir + "/" : "";
      if (prefix && !path.startsWith(prefix)) continue;
      const rel = path.slice(prefix.length);
      for (const rule of g.rules) {
        if (rule.dirOnly && !isDir) continue;
        if (rule.regex.test(rel)) ignored = !rule.negate;
      }
    }
    return ignored;
  }

  function isIgnored(filePath, gitignores) {
    const parts = filePath.split("/");
    for (let i = 1; i < parts.length; i++) {
      if (matchesIgnore(parts.slice(0, i).join("/"), true, gitignores)) return true; // a parent folder is ignored
    }
    return matchesIgnore(filePath, false, gitignores);
  }

  const NO_GITIGNORE_MESSAGE = "There's no .gitignore file for this part of your project, so nothing stops this file from being pushed to GitHub along with your code, secrets and all. If your .gitignore lives in a folder above the one you picked, pick that folder instead so we can see it.";
  const NOT_COVERED_MESSAGE = "Your .gitignore doesn't cover this file, so it will be pushed to GitHub the next time you commit.";
  const GITIGNORE_LINES = ".env*\n!.env.example";

  // entries: [{ path, text }]. Returns [{ path, finding }] for unprotected .env files.
  function checkGitignore(entries) {
    const gitignores = entries
      .filter((e) => e.path.split("/").pop() === ".gitignore")
      .map((e) => ({ dir: dirOf(e.path), rules: parseGitignore(e.text, dirOf(e.path)) }))
      .sort((a, b) => a.dir.length - b.dir.length); // top folder first, deeper ones override
    const problems = [];
    for (const e of entries) {
      if (!isEnvFile(e.path)) continue;
      if (isIgnored(e.path, gitignores)) continue;
      const applying = gitignores.filter((g) => !g.dir || e.path.startsWith(g.dir + "/"));
    let finding;
    if (applying.length) {
      const nearest = applying[applying.length - 1];
      const gitignorePath = nearest.dir ? nearest.dir + "/.gitignore" : ".gitignore";
      finding = {
        type: "Not protected from GitHub",
        message: NOT_COVERED_MESSAGE,
        fix: {
          text: "Add these lines to " + gitignorePath + ". If this file is already on GitHub, .gitignore won't remove it: also run git rm --cached " + e.path + " from the folder you scanned, and replace every secret inside.",
          code: GITIGNORE_LINES
        },
        setup: true
      };
    } else {
      const folder = dirOf(e.path);
      finding = {
        type: "Not protected from GitHub",
        message: NO_GITIGNORE_MESSAGE,
        fix: {
          text: "Create a file named .gitignore in " + (folder ? "the " + folder + " folder" : "the folder you scanned") + " with these lines:",
          code: GITIGNORE_LINES
        },
        setup: true
      };
    }
    problems.push({ path: e.path, finding });
  }
  return problems;
  }

  VC.checkGitignore = checkGitignore;
  VC.parseGitignore = parseGitignore;
  VC.isIgnored = isIgnored;
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
