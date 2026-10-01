// Vibe Check: Project scan
// Runs every check over a whole project folder and groups the results by file.
// Runs 100% in the browser. No network requests, no storage, no AI.

(function (VC) {
  "use strict";
  const { scan, isEnvFile, ENV_MESSAGE, checkGitignore, checkRls } = VC;

  function scanEntries(entries) {
    const results = [];
    for (const entry of entries) {
      if (entry.text.includes("\u0000")) continue; // binary file
      const findings = scan(entry.text);
      if (isEnvFile(entry.path)) {
        for (const f of findings) {
          if (f.exposed) continue; // a public name is a problem wherever it's written
          f.message = ENV_MESSAGE;
          f.fix = null;
          f.inEnv = true;
        }
      }
      if (findings.length) results.push({ path: entry.path, findings });
    }
    for (const problem of checkGitignore(entries.filter((e) => !e.text.includes("\u0000")))) {
      let group = results.find((g) => g.path === problem.path);
      if (!group) { group = { path: problem.path, findings: [] }; results.push(group); }
      group.findings.unshift(problem.finding);
    }
    const rls = checkRls(entries.filter((e) => !e.text.includes("\u0000")), { notes: true });
    for (const problem of rls.problems) {
      let group = results.find((g) => g.path === problem.path);
      if (!group) { group = { path: problem.path, findings: [] }; results.push(group); }
      group.findings.push(problem.finding);
      group.findings.sort((a, b) => (a.line || 0) - (b.line || 0));
    }
    results.sort((a, b) => a.path.localeCompare(b.path));
    results.note = rls.note;
    return results;
  }

  VC.scanEntries = scanEntries;
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
