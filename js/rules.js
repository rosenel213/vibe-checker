// Vibe Check: Secret rules
// What counts as a leaked secret, and how to find it in one piece of text.
// Runs 100% in the browser. No network requests, no storage, no AI.

(function (VC) {
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

  // Words in a setting's name that mean "this is a secret".
  const SECRET_NAME_WORDS = new Set(["SECRET", "PRIVATE", "PASSWORD", "PASSWD", "SERVICEROLE"]);
  // Services whose API keys are always secret (they bill you or give full access).
  const SECRET_SERVICES = new Set([
    "OPENAI", "ANTHROPIC", "CLAUDE", "GROQ", "GEMINI", "MISTRAL", "DEEPSEEK", "COHERE", "PERPLEXITY",
    "REPLICATE", "HUGGINGFACE", "ELEVENLABS", "RESEND", "SENDGRID", "MAILGUN", "TWILIO"
  ]);

  // Is a public setting name (like NEXT_PUBLIC_OPENAI_API_KEY) actually a secret?
  function publicNameLooksSecret(name) {
    const rest = name.replace(/^(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_/, "");
    const words = rest.split("_").filter(Boolean);
    const joined = [];
    for (let i = 0; i < words.length; i++) {
      joined.push(words[i]);
      if (i + 1 < words.length) joined.push(words[i] + words[i + 1]); // SERVICE_ROLE -> SERVICEROLE
    }
    if (joined.some((w) => SECRET_NAME_WORDS.has(w))) return true;
    if (words.some((w) => SECRET_SERVICES.has(w))) return true;
    if (/^(?:DATABASE|DB)_URL$/.test(rest)) return true;
    return false;
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
      type: "Secret marked public",
      regex: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]+\b/g,
      show: (m) => (publicNameLooksSecret(m[0]) ? m[0] : null),
      exposed: true,
      message: "Settings whose names start with NEXT_PUBLIC_, VITE_, REACT_APP_ or EXPO_PUBLIC_ are copied into your website and sent to every visitor's browser. This one is a secret, so if your site is live, it's already public. Remove the prefix, use the key only in server code (like an API route or a Supabase Edge Function), and replace the key, because the old one has been exposed."
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
          const line = lineOf(text, m.index);
          const duplicate = findings.some((f) => f.type === rule.type && f.line === line && f.value === shown);
          if (!duplicate) {
            findings.push({ type: rule.type, line, value: shown, message: rule.message, exposed: !!rule.exposed });
          }
        }
        if (m[0].length === 0) rule.regex.lastIndex++;
      }
    }
    findings.sort((a, b) => a.line - b.line);
    return findings;
  }

  VC.MAX_BYTES = MAX_BYTES;
  VC.mask = mask;
  VC.lineOf = lineOf;
  VC.isEnvFile = isEnvFile;
  VC.scan = scan;
  VC.ENV_MESSAGE = ENV_MESSAGE;
  VC.publicNameLooksSecret = publicNameLooksSecret;
  VC.RULES = RULES;
})(globalThis.VibeCheck = globalThis.VibeCheck || {});
