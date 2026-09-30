// Vibe Check: Tests
// Runs every practice set through the scanner and compares the results to the answer keys.
// Open tests.html in a browser to run them. Nothing is sent anywhere.

(function (VC) {
  "use strict";

  // Scans a practice folder the same way the page does: skip, then check everything else.
  function scanFolder(files) {
    const skipped = [];
    const entries = [];
    for (const f of files) {
      if (VC.skipReason(f.path, f.size)) skipped.push(f.path);
      else entries.push({ path: f.path, text: f.text });
    }
    const groups = VC.scanEntries(entries);
    const findings = groups.flatMap((g) => g.findings.map((x) => g.path + (x.line ? ":" + x.line : "") + " " + x.type));
    return { groups, findings: findings.sort(), skipped: skipped.sort(), note: groups.note };
  }

  function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

  function runAll() {
    const F = VC.fixtures;
    const results = [];
    function test(name, expected, got) {
      results.push({ name, pass: same(expected, got), expected, got });
    }

    // Piece 1: one file with 8 fake secrets on lines 15 to 22
    test("Piece 1: finds all 8 secrets in the practice file, on the right lines",
      [15, 16, 17, 18, 19, 20, 21, 22],
      VC.scan(F.piece1[0].text).map((f) => f.line));

    test("Piece 1: stays quiet on a safe line",
      0, VC.scan("const key = process.env.OPENAI_API_KEY;").length);

    // Piece 2: a whole project
    const p2 = scanFolder(F.piece2);
    test("Piece 2: finds the 6 secrets plus the unprotected .env",
      [".env Not protected from GitHub", ".env:3 Stripe live secret key", ".env:4 Database address with password",
       "keys/server.pem:1 Private key", "src/api/chat.js:8 OpenAI key", "src/config.js:5 GitHub token",
       "src/lib/supabase.js:8 Supabase service-role key"].sort(),
      p2.findings);
    test("Piece 2: skips node_modules and the image",
      ["node_modules/fake-lib/index.js", "public/logo.png"], p2.skipped);

    // Piece 3, check 1: .gitignore
    const g = scanFolder(F.gitignore);
    test("Check 1: flags exactly the 3 unprotected .env files",
      ["a-no-gitignore/.env Not protected from GitHub", "b-old-nextjs/.env Not protected from GitHub",
       "d-nested/app/.env Not protected from GitHub"],
      g.findings);
    const aMessage = g.groups.find((x) => x.path === "a-no-gitignore/.env").findings[0].message;
    test("Check 1: says 'no .gitignore' when there isn't one",
      true, aMessage.startsWith("There's no .gitignore"));

    // Piece 3, check 2: secrets marked public
    test("Check 2: flags exactly the 5 secrets marked public",
      [".env:5 Secret marked public", ".env:6 Secret marked public", ".env:7 Secret marked public",
       "src/chat.js:3 Secret marked public", "vite-app/src/ai.js:3 Secret marked public"],
      scanFolder(F.public).findings);

    // Piece 3, check 3: database tables
    const withSql = scanFolder(F.rlsWithSql);
    test("Check 3: flags the 2 open tables",
      ["supabase/migrations/20240101000000_init.sql:25 Table without protection",
       "supabase/migrations/20240101000000_init.sql:9 Table without protection"],
      withSql.findings);
    test("Check 3: shows the 'tables made in the website' note",
      VC.RLS_DASHBOARD_NOTE, withSql.note);

    const inner = scanFolder(F.rlsInnerFolder);
    test("Check 3: still shows the note when you pick the inner folder",
      VC.RLS_DASHBOARD_NOTE, inner.note);

    const noSql = scanFolder(F.rlsWithoutSql);
    test("Check 3: says it couldn't check when there are no .sql files",
      [0, VC.RLS_UNCHECKED], [noSql.findings.length, noSql.note]);

    // Small rule tests
    const ignoreCases = [
      [".env", ".env", true], [".env", "sub/.env", true], ["/.env", "sub/.env", false],
      [".env*", ".env.local", true], [".env*\n!.env.production", ".env.production", false],
      ["*.env", "prod.env", true], ["config/", "config/.env", true], ["**/.env", "a/b/.env", true],
      ["# .env", ".env", false], [".env*.local", ".env", false],
      ["secrets/*.env", "secrets/x.env", true], ["secrets/*.env", "other/secrets/x.env", false]
    ];
    const ignoreWrong = ignoreCases.filter(([rule, path, want]) =>
      VC.isIgnored(path, [{ dir: "", rules: VC.parseGitignore(rule, "") }]) !== want).map((c) => c[0] + " / " + c[1]);
    test("Rules: 12 .gitignore patterns behave like Git", [], ignoreWrong);

    const nameCases = [
      ["NEXT_PUBLIC_SUPABASE_URL", false], ["NEXT_PUBLIC_SUPABASE_ANON_KEY", false], ["NEXT_PUBLIC_MAPBOX_TOKEN", false],
      ["NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", false], ["NEXT_PUBLIC_SECRETARY_NAME", false], ["NEXT_PUBLIC_GOOGLE_MAPS_API_KEY", false],
      ["VITE_SUPABASE_SERVICE_ROLE_KEY", true], ["REACT_APP_JWT_SECRET", true], ["EXPO_PUBLIC_OPENAI_KEY", true],
      ["NEXT_PUBLIC_DATABASE_URL", true], ["VITE_ADMIN_PASSWORD", true], ["NEXT_PUBLIC_PRIVATE_KEY", true]
    ];
    const nameWrong = nameCases.filter(([name, want]) => (VC.scan("x = " + name + ";").length > 0) !== want).map((c) => c[0]);
    test("Rules: 12 public setting names judged correctly", [], nameWrong);

    return results;
  }

  VC.runAll = runAll;

  // Show results on tests.html
  if (typeof document !== "undefined" && document.getElementById("test-results")) {
    const out = document.getElementById("test-results");
    const results = runAll();
    const failed = results.filter((r) => !r.pass);
    const heading = document.createElement("h2");
    heading.className = failed.length ? "verdict bad" : "verdict good";
    heading.textContent = failed.length
      ? failed.length + " of " + results.length + " tests failed. Don't publish until these pass."
      : "All " + results.length + " tests passed.";
    out.append(heading);
    const list = document.createElement("ol");
    list.className = "test-list";
    for (const r of results) {
      const li = document.createElement("li");
      li.className = r.pass ? "pass" : "fail";
      li.textContent = (r.pass ? "PASS  " : "FAIL  ") + r.name;
      if (!r.pass) {
        const detail = document.createElement("pre");
        detail.textContent = "Expected: " + JSON.stringify(r.expected, null, 1) + "\nGot: " + JSON.stringify(r.got, null, 1);
        li.append(detail);
      }
      list.append(li);
    }
    out.append(list);
  }
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
