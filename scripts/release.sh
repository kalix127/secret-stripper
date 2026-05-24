#!/usr/bin/env bash
#
# Interactive release helper.
#
# 1. Refuses to run with a dirty working tree.
# 2. Prompts for patch/minor/major/explicit bump.
# 3. Generates a CHANGELOG.md block from `git log <last-tag>..HEAD` grouped
#    by Conventional Commit type.
# 4. Updates Cargo.toml + Cargo.lock with the new version.
# 5. Opens $EDITOR on CHANGELOG.md for review.
# 6. Creates the release commit + tag.
# 7. Optionally pushes (off by default).
#
# Never pushes without an explicit y.
#
# The Cloudflare Worker is intentionally NOT touched here - it only needs
# redeploy when the embedded installer scripts change. Run `wrangler deploy`
# manually for that, independently of version cuts.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if ! git diff-index --quiet HEAD --; then
  echo "error: working tree is dirty. Commit or stash before releasing." >&2
  exit 1
fi

current="$(grep -E '^version *= *"' Cargo.toml | head -n1 | sed -E 's/^version *= *"([^"]+)".*/\1/')"
if [[ -z "$current" ]]; then
  echo "error: could not parse current version from Cargo.toml" >&2
  exit 1
fi

IFS='.' read -r major minor patch <<<"$current"
patch_next="$major.$minor.$((patch + 1))"
minor_next="$major.$((minor + 1)).0"
major_next="$((major + 1)).0.0"

echo
echo "Current version: $current"
echo "Select bump:"
echo "  1) patch     -> $patch_next"
echo "  2) minor     -> $minor_next"
echo "  3) major     -> $major_next"
echo "  4) explicit  (you type the next version)"
echo
read -r -p "Choice [1-4]: " choice
case "$choice" in
  1) new="$patch_next" ;;
  2) new="$minor_next" ;;
  3) new="$major_next" ;;
  4)
    read -r -p "New version (e.g. 1.2.3): " new
    ;;
  *) echo "abort: invalid choice" >&2; exit 1 ;;
esac

if ! [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
  echo "error: '$new' is not a valid SemVer string" >&2
  exit 1
fi

if git rev-parse --verify "v$new" >/dev/null 2>&1; then
  echo "error: tag v$new already exists. Pick a higher version, or delete the" >&2
  echo "       existing tag first with:  git tag -d v$new && git push origin :refs/tags/v$new" >&2
  exit 1
fi

last_tag="$(git describe --tags --abbrev=0 --match 'v*.*.*' 2>/dev/null || true)"
if [[ -n "$last_tag" ]]; then
  range="$last_tag..HEAD"
else
  # First release (or post-cleanup test repo): cap the lookback so the
  # CHANGELOG doesn't ingest every commit since project start. 20 is a
  # round number that's plenty for an initial public cut.
  range="HEAD~20..HEAD"
  if ! git rev-parse --verify HEAD~20 >/dev/null 2>&1; then
    range="HEAD"
  fi
fi

echo
echo "Building CHANGELOG block from: ${range}"

# Group subject lines by Conventional Commit type. Output sections are
# Added / Fixed / Performance / Changed / Documentation / Other.
# Skip empty groups so the final block stays clean.
added=()
fixed=()
perf=()
changed=()
docs=()
other=()

while IFS= read -r subject; do
  [[ -z "$subject" ]] && continue
  case "$subject" in
    chore\(release\):*|chore:\ v[0-9]*) continue ;;
    feat\(*\):*|feat:*)         added+=("$subject") ;;
    fix\(*\):*|fix:*)           fixed+=("$subject") ;;
    perf\(*\):*|perf:*)         perf+=("$subject") ;;
    refactor\(*\):*|refactor:*) changed+=("$subject") ;;
    docs\(*\):*|docs:*)         docs+=("$subject") ;;
    *) other+=("$subject") ;;
  esac
done < <(git log "$range" --no-merges --pretty='%s')

# Strip the "type(scope): " prefix from each entry so the CHANGELOG bullets
# read naturally without re-stating the section name.
strip_prefix() {
  sed -E 's/^[a-z]+(\([^)]+\))?: *//'
}

emit_section() {
  local title="$1"
  shift
  local arr=("$@")
  if [[ ${#arr[@]} -eq 0 ]]; then
    return
  fi
  printf '### %s\n\n' "$title"
  for s in "${arr[@]}"; do
    printf -- '- %s\n' "$(echo "$s" | strip_prefix)"
  done
  printf '\n'
}

today="$(date +%F)"
tmp_block="$(mktemp)"
{
  printf '## [%s] - %s\n\n' "$new" "$today"
  emit_section "Added"          "${added[@]+"${added[@]}"}"
  emit_section "Fixed"          "${fixed[@]+"${fixed[@]}"}"
  emit_section "Performance"    "${perf[@]+"${perf[@]}"}"
  emit_section "Changed"        "${changed[@]+"${changed[@]}"}"
  emit_section "Documentation"  "${docs[@]+"${docs[@]}"}"
  emit_section "Other"          "${other[@]+"${other[@]}"}"
} > "$tmp_block"

# Patch CHANGELOG.md: insert the new block right after "## [Unreleased]" and
# rewrite the link references at the bottom.
changelog="CHANGELOG.md"
if [[ ! -f "$changelog" ]]; then
  echo "error: CHANGELOG.md not found at repo root" >&2
  exit 1
fi

tmp_changelog="$(mktemp)"
awk -v block_file="$tmp_block" '
  BEGIN { inserted = 0 }
  /^## \[Unreleased\]/ {
    print
    print ""
    while ((getline line < block_file) > 0) print line
    close(block_file)
    inserted = 1
    next
  }
  { print }
  END {
    if (!inserted) {
      print "INTERNAL: failed to locate [Unreleased] header in CHANGELOG.md" > "/dev/stderr"
      exit 1
    }
  }
' "$changelog" > "$tmp_changelog"

# Rewrite link references at the bottom: update [Unreleased] compare URL and
# append a new [<new>] tag reference if missing.
awk -v ver="$new" '
  /^\[Unreleased\]:/ {
    sub(/v[0-9]+\.[0-9]+\.[0-9]+\.\.\.HEAD/, "v" ver "...HEAD")
    print
    print "[" ver "]: https://github.com/kalix127/secret-stripper/releases/tag/v" ver
    next
  }
  { print }
' "$tmp_changelog" > "$changelog"

rm -f "$tmp_block" "$tmp_changelog"

# Bump Cargo.toml version (the FIRST `version = ` line - the package one).
sed -i -E '0,/^version = "/{ s/^version = "[^"]+"/version = "'"$new"'"/ }' Cargo.toml

# Refresh Cargo.lock package version.
cargo update -p secret-stripper >/dev/null 2>&1 || true

echo
echo "--- staged changes ---"
git --no-pager diff -- Cargo.toml Cargo.lock CHANGELOG.md
echo "--- end staged changes ---"
echo
echo "Edit CHANGELOG.md by hand now if you want to tweak the bullets, then re-run."
echo
read -r -p "Commit and tag v$new? [y/N]: " do_commit
if [[ "${do_commit:-}" != "y" && "${do_commit:-}" != "Y" ]]; then
  echo "aborted before commit. Cargo.toml, Cargo.lock and CHANGELOG.md are modified;"
  echo "run 'git checkout -- Cargo.toml Cargo.lock CHANGELOG.md' to undo."
  exit 0
fi

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): v$new"
# Annotated tag (not lightweight) so `git push --follow-tags` actually
# ships it. Without -a, the tag stays local and release.yml never fires.
git tag -a "v$new" -m "v$new"

echo
echo "Created commit and tag v$new on $(git rev-parse --abbrev-ref HEAD)."
echo

read -r -p "Push to origin now? [y/N]: " do_push
if [[ "${do_push:-}" != "y" && "${do_push:-}" != "Y" ]]; then
  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  echo "skipped push. When ready, run:"
  echo "  git push --follow-tags origin $current_branch"
  exit 0
fi

current_branch="$(git rev-parse --abbrev-ref HEAD)"
git push --follow-tags origin "$current_branch"
echo
echo "Pushed v$new. release.yml will start on GitHub now."
