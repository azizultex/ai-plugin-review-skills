# WordPress Plugin Review Skills for Claude Code

Custom Claude Code slash commands that audit WordPress plugins for compliance with WordPress.org Plugin Review Team guidelines — before you submit.

Built from real rejection feedback received from the WordPress.org review team, combined with prompts refined across ChatGPT, Claude, and Grok.

---

## Skills Included

| Command | What It Does |
|---|---|
| `/wp-plugin-review` | Full 33-category compliance and security audit |
| `/wp-security-scan` | Focused scan covering 13 security vulnerability categories |

Both commands automatically scan the plugin in the current directory. No arguments needed.

---

## Installation

### One-liner install (recommended)

Run this in your terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/azizultex/ai-plugin-review-skills/main/install.sh | bash
```

The installer will ask whether you want to install **globally** (available in all your projects) or **per-project** (only in the current directory).

> **Global install** is recommended — the skills will be available whenever you open any plugin in Claude Code.

---

### Manual install (alternative)

**Global** — available in all projects:

```bash
mkdir -p ~/.claude/commands
curl -fsSL https://raw.githubusercontent.com/azizultex/ai-plugin-review-skills/main/.claude/commands/wp-plugin-review.md -o ~/.claude/commands/wp-plugin-review.md
curl -fsSL https://raw.githubusercontent.com/azizultex/ai-plugin-review-skills/main/.claude/commands/wp-security-scan.md -o ~/.claude/commands/wp-security-scan.md
```

**Per-project** — only in your current plugin directory:

```bash
mkdir -p .claude/commands
curl -fsSL https://raw.githubusercontent.com/azizultex/ai-plugin-review-skills/main/.claude/commands/wp-plugin-review.md -o .claude/commands/wp-plugin-review.md
curl -fsSL https://raw.githubusercontent.com/azizultex/ai-plugin-review-skills/main/.claude/commands/wp-security-scan.md -o .claude/commands/wp-security-scan.md
```

---

## Usage

Open your plugin folder in Claude Code, then type:

```
/wp-plugin-review
```

Claude will:
1. Detect your plugin name, slug, and text domain from the main plugin file header
2. Scan all PHP, JS, CSS, readme.txt, and build artifact files recursively
3. Report only the issues actually found — no noise from passing checks
4. Group issues by severity: Blocker, High, Medium, Low

For a security-only scan:

```
/wp-security-scan
```

---

## What Gets Checked

### Full Review (`/wp-plugin-review`) — 33 categories

**Compliance**
- Missing `composer.json` when Composer is used
- No publicly documented source for minified/compiled JS or CSS
- Calling core loading files directly (`wp-load.php`, `wp-config.php`, `wp-blog-header.php`)
- Incorrect file/directory path references (hardcoded paths instead of WP functions)
- Text domain does not match plugin slug
- Plugin permalink does not match text domain
- Processing entire `$_POST` / `$_GET` / `$_REQUEST` input arrays
- Generic or short function/class/constant/namespace prefixes (under 4 characters)
- Unprefixed options and transients
- Outdated third-party libraries
- Combined or renamed JavaScript files
- Using cURL instead of WordPress HTTP API
- Scripts/styles echoed directly instead of using `wp_enqueue_*`
- Setting a default timezone with `date_default_timezone_set()`
- Including libraries already in WordPress core
- Loading remote files from CDNs
- Trademark infringement in plugin display name
- Incorrect or mismatched Stable Tag in readme.txt
- Changing other plugins' activation status
- Unclosed `ob_start()`
- Keyword stuffing in readme.txt

**Security**
- Unsafe SQL calls (SQL injection risk)
- Unescaped output (XSS vulnerabilities)
- Unsanitized input (`$_POST`, `$_GET`, `$_SERVER`)
- Stored XSS from imported external data
- Missing direct file access protection (`ABSPATH` check)
- Missing or bypassable nonce verification
- Missing user capability checks
- Arbitrary CSS/JS/PHP insertion
- Powered By / credit links displayed without explicit opt-in
- REST API routes missing or using improper `permission_callback`
- Hardcoded admin-ajax URL in JavaScript (must use `wp_localize_script`)
- Invalid or unresolvable plugin/author URIs in plugin header

### Security Scan (`/wp-security-scan`) — 13 categories

- SQL injection
- XSS via unescaped output
- Stored XSS via unsanitized external data
- Unsanitized user input
- Missing or bypassable nonce verification
- Missing user capability checks
- Arbitrary code execution (`eval`, PHP injection)
- Arbitrary script insertion (JS/CSS saved and rendered)
- Missing direct file access protection
- Direct database connections bypassing `$wpdb`
- Insecure HTTP requests via cURL
- REST API routes missing or using improper `permission_callback`
- Sensitive data exposure (hardcoded credentials, debug output)

---

## Tips

- Fix all **Blocker** and **High** severity issues before submitting to WordPress.org
- Issues found inside `vendor/` third-party libraries are noted separately — they are generally acceptable
- Run `/wp-plugin-review` before every major release, not just before first submission
- The security scan is faster — use it during active development, the full review before submission
