---
name: skills-corpus-sync
description: "Use when pushing Hermes skills or any local repo to GitHub."
version: 1.0.0
author: curator
license: MIT
metadata:
  hermes:
    tags: [GitHub, git, backup, sync, skills, rebase, tokens]
---

# Hermes Skills Corpus → GitHub Sync

## When to Use

Trigger on any of: "day skills len github" / "backup skills" / "push skills to GitHub", any request to sync `~/.hermes/skills` to `Cstrien/Skills_Dior`, or generic repo-sync work where the remote is ahead, the working tree is dirty, and the push then 401s. Also use when a GitHub token has gone stale and you must diagnose which store holds the dead credential.

Recurring user task ("day het skills len github" / push skills lên GitHub). Covers BOTH the generic sync workflow AND the repo-specific state, because a future session will likely find the same conditions: concurrent pushers, embedded dead tokens, curator backups accumulating.

> Note: the bundled `github-repo-management` / `github-auth` skills cover generic GitHub ops but have NO corpus-sync workflow and no stale-token diagnosis — that's why this skill exists.

## Repo state (as of 2026-09-16, re-verify each session)

- Local: `~/.hermes/skills` — git repo, branch `master`, ~285 MB, ~383 SKILL.md files
- Remote: `https://github.com/Cstrien/Skills_Dior` (public), remote URL embeds a PAT
- Other Hermes sessions push concurrently — remote is often AHEAD of local. Never assume local-only state; fetch first.
- History commits use style: `Backup: 1079 Hermes skills (security, pentesting, AI/ML, creative, dev)`

## Sync workflow (validated)

1. **Recon** (batch these):
   - `git status --porcelain | awk '{print $1}' | sort | uniq -c` — count new/modified/deleted
   - `git status --porcelain | grep "^??"` — list untracked (review: new skills + refs)
   - `git fetch origin && git rev-list --left-right --count master...origin/master` — divergence
2. **Secret scan BEFORE `git add -A`**:
   `grep -rEn "ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}"` — pentest skill scripts legitimately contain attack strings and secret-pattern references; exclude lines matching `pattern|regex|example|detect|scan`; escalate only real-looking hits.
3. **Commit local changes BEFORE pulling** — `git add -A && git commit -m "Add N new skills + updates: <topics>, cleanup curator backups"`
4. **`git pull --rebase origin master`**. It refuses on unstaged changes ("cannot pull with rebase: You have unstaged changes") — hence step 3 first.
5. **Conflict pattern in this corpus: additive edits, HEAD side EMPTY, all content on incoming side.** Resolution:
   ```bash
   sed -i '/^<<<<<<< HEAD$/d; /^=======$/d; /^>>>>>>> /d' <files>
   grep -c "<<<<<<<" <files>   # must be 0 per file
   git add -A && GIT_EDITOR=true git rebase --continue
   ```
6. **Delete stale `.curator_backups/<old-timestamps>/`** in the same commit — weekly curator backups accumulate tar.gz files and inflate the repo.
7. **Push**; on auth failure → rotate (below). Check `git log origin/master` before writing a commit message that duplicates the other session's work.

## Stale-token diagnosis (2026-09-16 finding)

Tokens silently expire and live in MULTIPLE stores that do NOT sync:

| Store | Location |
|-------|----------|
| embedded remote URL | `<repo>/.git/config` — `https://user:TOKEN@github.com/...` |
| gh CLI | `~/.config/gh/hosts.yml` (`oauth_token:`, listed twice when both per-user and top-level) |
| git credential store | `~/.git-credentials` |
| Hermes env | `~/.hermes/.env` (`GITHUB_TOKEN=`, if any) |

Validate all of them (401 = dead):
```python
import re, urllib.request
cfg = open('/home/kali/.config/gh/hosts.yml').read()  # or .git/config / .git-credentials
for t in dict.fromkeys(re.findall(r'(?:oauth_token:\s*|https://[^:@/]+:)([^@\s]+)@?', cfg)):
    req = urllib.request.Request('https://api.github.com/user')
    req.add_header('Authorization', 'token ' + t)
    try: urllib.request.urlopen(req); print(t[:6], 'VALID')
    except Exception as e: print(t[:6], e.code if hasattr(e,'code') else e)
```

Pitfalls learned:
- On a PUBLIC repo, fetch/clone succeed even with a dead token. First symptom is push: `remote: Invalid username or token. Password authentication is not supported for Git operations.`
- `gh --version && gh auth status || echo "gh not installed"` prints "gh not installed" when gh IS installed but its token is invalid — the `||` conflates the two. Check `command -v gh` separately.
- `gh auth status` showing "The token ... is invalid" means expiry/revocation — diagnose and rotate, don't retry.

## Auth rotation options (user chose SSH in 2026-09-16 session)

1. **SSH key** (chosen): `ssh-keygen -t ed25519 -C hermes-kali -f ~/.ssh/id_ed25519 -N ""`; hand pubkey to user → https://github.com/settings/ssh/new. Then:
   - `ssh-keyscan github.com >> ~/.ssh/known_hosts` — otherwise `ssh -T git@github.com` fails with `Host key verification failed` in non-interactive sessions
   - `git remote set-url origin git@github.com:Cstrien/Skills_Dior.git` — also strips the dead token from disk (hygiene)
   - `ssh -T git@github.com` → expect `Hi Cstrien!` → push
2. **Fresh PAT**: user generates at github.com/settings/tokens (scope: repo); update remote URL or `gh auth login --with-token`.
3. **Device flow**: `gh auth login` — user declined this session.

## State carried over from 2026-09-16 session

Session ended MID-RECOVERY: ed25519 key `hermes-kali` generated and handed to the user; SSH path NOT yet verified end-to-end (user hadn't confirmed adding the key). Local commits were made and rebased onto origin/master; push pending auth. Next session: run the recon step first to see if the other session/user already pushed, then complete the push via whichever auth is now valid.
