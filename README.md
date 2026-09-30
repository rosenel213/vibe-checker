# Vibe Check: Secret Scanner

Check your code or your whole project folder. If you've leaked a password or API key, Vibe Check tells you straight, and tells you how to fix it.

**Try it:** https://rosenel213.github.io/vibe-checker/

## Your code never leaves your browser

The scan runs entirely on your own computer. Nothing is uploaded, saved, logged, or sent anywhere. There's no server, no database, no tracking, and no AI.

Don't just take our word for it. You can check:

- **Read the code.** It's three small files in this repository. `script.js` does all the scanning and contains no network requests.
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

Found secrets are always shown masked (like `sk-p...1234`), never in full.

## What it doesn't do

Brutal honesty, because a security tool that oversells itself is dangerous:

- It only looks for the secret types listed above. Other kinds of keys can slip through.
- When scanning a folder, it skips downloaded and generated files (like `node_modules`), images, lock files, and files over 1 MB. It always tells you what it skipped.
- It does not check your login system, database rules, or anything else about your app's security.
- **A clean result does not mean your app is safe.** It means we didn't find these specific leaks.

## Found a key? Deleting it isn't enough

Once a key has been in your code, assume it's stolen. It stays in your git history and in past deployments. Create a new key, cancel the old one, and keep keys in environment variables on your server.

## Found a bug?

If the scanner missed a real secret or flagged something harmless, please open an issue in this repository. Never paste a real, working key into an issue. Describe it or use a fake one.

## Coming next

This is piece 1 of a bigger checker for vibe-coded apps, built slowly on purpose, so every piece is tested before the next one starts:

1. Secret scanner (done)
2. Scan a whole project at once (done)
3. Checks for common Next.js + Supabase mistakes (you're here: `.gitignore` check done)
4. Plain-English explanations of every finding
5. A map that explains your own code to you
6. A grade and shareable report card
