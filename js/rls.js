// Vibe Check: Check: Supabase tables without Row Level Security
// Reads .sql setup files and flags tables anyone could read or change.
// Runs 100% in the browser. No network requests, no storage, no AI.

(function (VC) {
  "use strict";
  const { lineOf } = VC;

  // ---------- Check: Supabase tables without Row Level Security ----------

  // Replaces SQL comments with spaces, keeping line numbers the same.
  function stripSqlComments(sql) {
    return sql
      .replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, " "))
      .replace(/--[^\n]*/g, (c) => " ".repeat(c.length));
  }

  const SQL_IDENT = '(?:"[^"]+"|[A-Za-z_][\\w$]*)';
  const SQL_NAME = "(?:(" + SQL_IDENT + ")\\s*\\.\\s*)?(" + SQL_IDENT + ")";

  function sqlIdent(raw) {
    if (!raw) return null;
    return raw.startsWith('"') ? raw.slice(1, -1) : raw.toLowerCase();
  }

  const RLS_MESSAGE = "Row Level Security is off for this table. Your public Supabase key is in every visitor's browser, so anyone can use it to read, change, or delete everything in this table. Turn it on with: alter table TABLE_NAME enable row level security; then add policies that say who can see and change what.";
  const RLS_UNCHECKED = "We couldn't check your database tables. This project uses Supabase, but it has no database setup files (.sql), which usually means the tables were made in the Supabase website. Check them there: any table marked as unrestricted or with RLS disabled is open to anyone.";
  const RLS_DASHBOARD_NOTE = "We checked the tables in your .sql setup files. Tables made directly in the Supabase website aren't in those files, so check those there too.";

  // entries: [{ path, text }]. Returns { problems: [{ path, finding }], note: string | null }
  function checkRls(entries, options) {
    const events = [];
    const sqlFiles = entries.filter((e) => /\.sql$/i.test(e.path) || e.path === "Pasted code").sort((a, b) => a.path.localeCompare(b.path));
    sqlFiles.forEach((file, fileIndex) => {
      const sql = stripSqlComments(file.text);
      const patterns = [
        ["create", new RegExp("\\bcreate\\s+(?:(?:global\\s+|local\\s+)?(temp|temporary)\\s+|unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?" + SQL_NAME, "gi")],
        ["rls", new RegExp("\\balter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?" + SQL_NAME + "\\s+(enable|disable)\\s+row\\s+level\\s+security", "gi")],
        ["drop", new RegExp("\\bdrop\\s+table\\s+(?:if\\s+exists\\s+)?" + SQL_NAME, "gi")]
      ];
      for (const [kind, regex] of patterns) {
        let m;
        while ((m = regex.exec(sql)) !== null) {
          events.push({ kind, m, fileIndex, index: m.index, file });
        }
      }
    });
    events.sort((a, b) => a.fileIndex - b.fileIndex || a.index - b.index);

    const tables = new Map(); // "schema.table" -> { path, line, name, rls }
    for (const ev of events) {
      const m = ev.m;
      if (ev.kind === "create") {
        if (m[1]) continue; // temporary table
        const schema = sqlIdent(m[2]) || "public";
        if (schema !== "public") continue; // only the public schema is reachable with the public key
        const name = sqlIdent(m[3]);
        tables.set(schema + "." + name, { path: ev.file.path, line: lineOf(ev.file.text, m.index), name, rls: false });
      } else {
        const schema = sqlIdent(m[1]) || "public";
        const key = schema + "." + sqlIdent(m[2]);
        if (!tables.has(key)) continue;
        if (ev.kind === "drop") tables.delete(key);
        else tables.get(key).rls = m[3].toLowerCase() === "enable";
      }
    }

    const problems = [];
    for (const t of tables.values()) {
      if (t.rls) continue;
      problems.push({ path: t.path, finding: { type: "Table without protection", line: t.line, value: t.name, message: RLS_MESSAGE, setupDb: true } });
    }

    let note = null;
    if (options && options.notes) {
      const foundTables = events.some((e) => e.kind === "create");
      if (foundTables) note = RLS_DASHBOARD_NOTE;
      else if (entries.some((e) => /supabase/i.test(e.path + "\n" + e.text))) note = RLS_UNCHECKED;
    }
    return { problems, note };
  }

  VC.checkRls = checkRls;
  VC.RLS_UNCHECKED = RLS_UNCHECKED;
  VC.RLS_DASHBOARD_NOTE = RLS_DASHBOARD_NOTE;
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
