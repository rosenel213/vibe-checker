# Vibe Check: Secret Scanner

Check your code or your whole project folder. If you've leaked a password or API key, Vibe Check tells you straight, and tells you how to fix it.

**Try it:** https://rosenel213.github.io/vibe-checker/

## Your code never leaves your browser

The scan runs entirely on your own computer. Nothing is uploaded, saved, logged, or sent anywhere. There's no server, no database, no tracking, and no AI.

Don't just take our word for it. You can check:

- **Read the code.** It's three small files in this repository. The code is a few small files in this repository (listed below), and none of them make network requests.
- **Look at the security setting.** `index.html` includes a Content-Security-Policy with `connect-src 'none'`, which tells your browser to block the page from sending data anywhere.
- **Watch it yourself.** Open your browser's developer tools, go to the Network tab, and run a scan. You'll see no requests.

## What it finds

- OpenAI API keys
- AWS access keys and secret keys
- Stripe live secret keys
- Supabase service-role keys (the public "anon" key is ignored, because it's meant to be public)
- GitHub tokens
- Database addresses with passwords in them
- Private keys

It also checks that your `.env` files are protected by `.gitignore`, so they can't be pushed to GitHub by accident. This includes the common gap in older Next.js projects, where `.gitignore` only covers `.env*.local` and leaves plain `.env` unprotected.

It also catches secrets marked public: settings named `NEXT_PUBLIC_...`, `VITE_...`, `REACT_APP_...` or `EXPO_PUBLIC_...` get sent to every visitor's browser, so a secret with one of those names is a leaked secret. Public-by-design keys (like the Supabase anon key or Stripe publishable key) are left alone.

For Supabase projects, it reads your `.sql` database setup files and flags tables without Row Level Security, which anyone can read and change using your public key. If there are no setup files (tables made in the Supabase website), it says it couldn't check, instead of staying quiet.

Every finding says why it's dangerous and exactly what to do, using the real names from your project, like `alter table public.todos enable row level security;`.

Found secrets are always shown masked (like `sk-p...1234`), never in full.

## What it doesn't do

Brutal honesty, because a security tool that oversells itself is dangerous:

- It only looks for the secret types listed above. Other kinds of keys can slip through.
- When scanning a folder, it skips downloaded and generated files (like `node_modules`), images, lock files, and files over 1 MB. It always tells you what it skipped.
- It does not check your login system, database rules, or anything else about your app's security.
- **A clean result does not mean your app is safe.** It means we didn't find these specific leaks.

## Run the tests yourself

Open **https://rosenel213.github.io/vibe-checker/tests.html**. It runs the scanner on practice files with known answers, right in your browser, and shows PASS or FAIL for each. If anything fails, don't trust the scanner until it's fixed.

## How the code is organized

Each file has one job:

| File | Job |
|---|---|
| `index.html` | The scanner page |
| `tests.html` | The tests page |
| `style.css` | How everything looks |
| `js/rules.js` | What counts as a leaked secret |
| `js/folder.js` | Which files in a folder get skipped |
| `js/gitignore.js` | Check: `.env` files protected by `.gitignore` |
| `js/rls.js` | Check: Supabase tables without Row Level Security |
| `js/project.js` | Runs every check over a whole folder |
| `js/page.js` | Connects the buttons and results on the page |
| `tests/fixtures.js` | The practice files, used by the tests |
| `tests/tests.js` | The tests and their answer keys |

## Found a key? Deleting it isn't enough

Once a key has been in your code, assume it's stolen. It stays in your git history and in past deployments. Create a new key, cancel the old one, and keep keys in environment variables on your server.

## Found a bug?

If the scanner missed a real secret or flagged something harmless, please open an issue in this repository. Never paste a real, working key into an issue. Describe it or use a fake one.

## Coming next

This is piece 1 of a bigger checker for vibe-coded apps, built slowly on purpose, so every piece is tested before the next one starts:

1. Secret scanner (done)
2. Scan a whole project at once (done)
3. Checks for common Next.js + Supabase mistakes (done)
4. Plain-English explanations of every finding (you're here: every finding now includes the exact fix, with your real file, table, and setting names)
5. A map that explains your own code to you
6. A grade and shareable report card
