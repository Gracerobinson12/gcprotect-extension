# GC Protect — AI Data Privacy Extension

Open source Chrome extension that tokenizes sensitive data in your prompts
before they reach ChatGPT, Claude, Gemini, Perplexity, and Grok.

**Website:** https://www.gcprotect.tech
**Chrome Web Store:** [coming soon]

## What it does

GC Protect scans every prompt you type into supported AI platforms. If it
detects sensitive data (names, emails, SSNs, API keys, addresses, etc.), it
replaces each value with a cryptographic token before the prompt is sent.
Real values stay in your browser; only tokens reach the AI provider.

Real values are restored in the AI's response on your screen, so you still
see "Dear Jane Doe" even though the AI only ever saw "Dear ⟨NM4K7J2A9Q⟩".

## Why open source

A privacy tool nobody can audit isn't privacy. The source for the extension
you run in your browser lives here, under MIT license, for anyone to verify.

## Install

- Chrome Web Store: pending review
- Manual install: https://www.gcprotect.tech

## Security

Report security issues to intel@gratiacore.com. See SECURITY.md.

## License

MIT. See LICENSE.

Built by Gratia Core Enterprise LLC.
