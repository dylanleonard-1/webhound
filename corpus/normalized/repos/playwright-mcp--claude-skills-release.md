# Preparing a Release

Most MCP source lives upstream at `~/playwright/packages/playwright-core/src/tools/` (and `tests/mcp/`). A release combines an upstream Playwright roll, a version bump in this repo, and release notes that draw from both.

## 1. Roll Playwright

Follow the "Rolling Playwright" steps in `CLAUDE.md`: run `node roll.js`, branch as `roll-pw-`, run `npm test`, and open a `chore: roll Playwright to ` PR. **Wait for it to merge into `main`** before proceeding.

## 2. Bump the version (PR off `main`)

```bash
git checkout main && git pull
git checkout -b mark-v0.0.
# Bump "version" in package.json, package-lock.json (both occurrences), and server.json (both occurrences)
git commit -am "chore: mark v0.0."
git push -u origin mark-v0.0.
gh pr create --repo microsoft/playwright-mcp --head :mark-v0.0. \
  --title "chore: mark v0.0." --body "## Summary
- Bump version to 0.0."
```

## 3. Find the cutoff

```bash
# Last published release and its date
gh release list --repo microsoft/playwright-mcp --limit 5

# Format reference — use the most recent non-trivial release
gh release view v0.0. --repo microsoft/playwright-mcp

# Playwright version that shipped in the last release
git show :package.json | grep -E '"playwright|"@playwright"'
# Convert the alpha timestamp to a UTC date for the upstream log filter
date -r  -u
```

## 4. Collect changes

```bash
# Upstream playwright (MCP code path widened to catch tools/cli/dashboard/extension too)
cd ~/playwright
git log --since="" --until="" --oneline -- \
  packages/playwright-core/src/tools/ packages/playwright-core/src/extension/ tests/mcp/

# This repo
cd -
git log ..HEAD --oneline
```

Filter for `feat(mcp)`, `fix(mcp)`, `feat(extension)`, `fix(extension)`, and dashboard changes. Many extension PRs land in *both* repos because the extension source lives upstream now — prefer the `microsoft/playwright` PR link. Use `git show  --stat` to disambiguate when a commit subject is ambiguous. Drop reverted commits, test-only changes, docs, and anything not user-visible.

## 5. Write `release-notes.md`

Follow the format from the prior release: `## What's New` (with `### New Tools`, `### Tool Improvements`, optional `### Browser Extension`, `### Dashboard`, `### Other Changes`) and `## Bug Fixes`. Link each entry to its PR (`[#NNNNN](https://github.com/microsoft/playwright/pull/NNNNN)` or the playwright-mcp equivalent). **Do not mention features that are not yet enabled by default** — confirm with the user before listing experimental flags.

## 6. Create the draft release

```bash
gh release create v0.0. --repo microsoft/playwright-mcp \
  --draft --title "v0.0." --target main \
  --notes-file release-notes.md
```

Publish the draft once the mark PR is merged.
