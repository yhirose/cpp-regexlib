#!/usr/bin/env bash
#
# Release a new version of cpp-regexlib.
#
# Usage: ./release.sh [--run] [--minor | --major]
#
# By default, runs in dry-run mode (no changes made).
# Pass --run to actually update files, commit, tag, and push.
# Pass --minor to force a minor bump even when the ABI is unchanged
# (use this for behavioral breaking changes that don't break ABI).
# Pass --major to force a major bump.
#
# This script:
#   1. Reads the current version from regexlib.h
#   2. Checks that the working directory is clean
#   3. Verifies CI status of the latest commit (all must pass except abidiff,
#      which decides the bump, and the informational Benchmark workflow)
#   4. Determines the next version automatically:
#        - abidiff passed  → patch bump (e.g., 0.1.0 → 0.1.1)
#        - abidiff failed  → minor bump (e.g., 0.1.1 → 0.2.0)
#        - --minor passed  → forces minor bump regardless of abidiff
#        - --major passed  → forces major bump (e.g., 0.9.1 → 1.0.0)
#      Exception: if the repository has no release tag yet, the version already
#      in regexlib.h is released as-is (there is nothing to bump from).
#   5. Updates regexlib.h
#   6. Commits, tags (vX.Y.Z), and pushes

set -euo pipefail

cd "$(dirname "$0")/.."

# Workflows whose result must not block a release. Benchmark is informational
# (throughput numbers, third-party engines fetched from the network), so a red
# or flaky run there says nothing about the correctness of the release.
INFORMATIONAL_RE='^Benchmark$'

DRY_RUN=1
FORCE_MINOR=0
FORCE_MAJOR=0
while [ $# -gt 0 ]; do
  case "$1" in
    --run)
      DRY_RUN=0
      shift
      ;;
    --minor)
      FORCE_MINOR=1
      shift
      ;;
    --major)
      FORCE_MAJOR=1
      shift
      ;;
    *)
      echo "Usage: $0 [--run] [--minor | --major]"
      exit 1
      ;;
  esac
done

if [ "$FORCE_MINOR" -eq 1 ] && [ "$FORCE_MAJOR" -eq 1 ]; then
  echo "Usage: $0 [--run] [--minor | --major]"
  exit 1
fi

version_hex() { # 1.2.3 -> 0x010203
  local major minor patch
  IFS='.' read -r major minor patch <<< "$1"
  printf "0x%02x%02x%02x" "$major" "$minor" "$patch"
}

# Publish a release: the branch and the tag go up in one atomic push, so a
# failure can never leave a tag on the remote pointing at a commit the remote
# branch does not have. $2 is the command that undoes the local state, printed
# on failure — without it the tree is clean again and a re-run would compute
# yet another bump on top of the commit that was never published.
tag_and_push() { # $1 = version, $2 = undo command
  echo "==> Tagging..."
  git tag "v$1"

  echo ""
  echo "==> Pushing..."
  if ! git push --atomic origin HEAD "v$1"; then
    echo ""
    echo "Error: push failed; nothing was published."
    echo "       Undo the local release with: $2"
    exit 1
  fi

  echo ""
  echo "==> Released v$1"
}

# --- Step 1: Read current version from regexlib.h ---
CURRENT_VERSION=$(sed -n 's/^#define REGEXLIB_VERSION "\([^"]*\)"/\1/p' regexlib.h)
CURRENT_VERSION_NUM=$(sed -n 's/^#define REGEXLIB_VERSION_NUM \(0x[0-9a-fA-F]*\).*/\1/p' regexlib.h)

if [ -z "$CURRENT_VERSION" ] || [ -z "$CURRENT_VERSION_NUM" ]; then
  echo "Error: could not read REGEXLIB_VERSION / REGEXLIB_VERSION_NUM from regexlib.h"
  exit 1
fi

IFS='.' read -r V_MAJOR V_MINOR V_PATCH <<< "$CURRENT_VERSION"

# The two macros are edited together; a mismatch would ship a version that
# consumers gating on REGEXLIB_VERSION_NUM would read incorrectly.
EXPECTED_NUM=$(version_hex "$CURRENT_VERSION")
if [ "$CURRENT_VERSION_NUM" != "$EXPECTED_NUM" ]; then
  echo "Error: REGEXLIB_VERSION_NUM ($CURRENT_VERSION_NUM) does not match"
  echo "       REGEXLIB_VERSION $CURRENT_VERSION (expected $EXPECTED_NUM)"
  exit 1
fi

echo "==> Current version: $CURRENT_VERSION ($CURRENT_VERSION_NUM)"

# --- Step 2: Check working directory is clean ---
if [ -n "$(git status --porcelain)" ]; then
  echo "Error: working directory is not clean"
  exit 1
fi

# --- Step 3: Check CI status of the latest commit ---
echo ""
echo "==> Checking CI status of the latest commit..."

HEAD_SHA=$(git rev-parse HEAD)
HEAD_SHORT=$(git rev-parse --short HEAD)
echo "    Latest commit: $HEAD_SHORT"

# Fetch all workflow runs for the HEAD commit. A commit can accumulate multiple
# runs of the same workflow (reruns, superseded runs that GitHub cancels via
# concurrency groups), so judge only the most recent run of each workflow.
# Skipped runs are dropped first: they carry no verdict, and abidiff gates its
# job off for same-repo pull_request events, so a commit that was a PR head
# collects a skipped twin of its push run — picking that one would read as a
# missing (or worse, a failing) ABI check.
RUNS=$(gh run list --commit "$HEAD_SHA" \
         --json name,status,conclusion,headSha,createdAt |
       jq '[.[] | select(.conclusion != "skipped")]
           | [group_by(.name)[] | max_by(.createdAt)]')

NUM_RUNS=$(echo "$RUNS" | jq 'length')

if [ "$NUM_RUNS" -eq 0 ]; then
  echo "Error: No CI runs found for commit $HEAD_SHORT."
  echo "       Wait for CI to complete before releasing."
  exit 1
fi

echo "    Found $NUM_RUNS workflow run(s):"

FAILED=0
RUNNING=0
ABIDIFF_FOUND=0
ABIDIFF_PASSED=0
while IFS=$'\t' read -r name status conclusion; do
  if [[ "$name" =~ $INFORMATIONAL_RE ]]; then
    echo "      [ -- ] $name (informational, ignored)"
    continue
  fi

  # A run that hasn't completed yet has an empty conclusion; don't treat it as
  # a failure — the release should wait until CI finishes.
  if [ "$status" != "completed" ]; then
    echo "      [ .. ] $name (still running)"
    RUNNING=1
    continue
  fi

  # Matched by exact name: a substring match would route any future workflow
  # whose name happens to contain "abi" into this branch, where a failure is
  # read as an ABI break instead of blocking the release.
  if [ "$name" = "abidiff" ]; then
    ABIDIFF_FOUND=1
    if [ "$conclusion" = "success" ]; then
      echo "      [ OK ] $name"
      ABIDIFF_PASSED=1
    elif [ "$conclusion" = "failure" ]; then
      echo "      [FAIL] $name ($conclusion) → ABI break detected, minor bump"
      ABIDIFF_PASSED=0
    else
      # cancelled / timed_out / startup_failure say nothing about the ABI, and
      # guessing a bump from them would ship a wrong version number.
      echo "      [FAIL] $name ($conclusion) → inconclusive, cannot pick a bump"
      FAILED=1
    fi
    continue
  fi

  if [ "$conclusion" = "success" ]; then
    echo "      [ OK ] $name"
  else
    echo "      [FAIL] $name ($conclusion)"
    FAILED=1
  fi
done < <(echo "$RUNS" | jq -r '.[] | [.name, .status, .conclusion] | @tsv')

if [ "$RUNNING" -eq 1 ]; then
  echo ""
  echo "Error: Some CI checks are still running. Wait for them to complete before releasing."
  exit 1
fi

if [ "$FAILED" -eq 1 ]; then
  echo ""
  echo "Error: Some CI checks failed. Fix them before releasing."
  exit 1
fi

echo "    All blocking CI checks passed."

if [ "$ABIDIFF_FOUND" -eq 0 ]; then
  echo ""
  echo "Warning: No abidiff run found for this commit; assuming ABI unchanged."
  echo "         Use --minor or --major to override the bump type."
  ABIDIFF_PASSED=1
fi

# --- Step 4: Determine new version ---
# With no tag in the repository there is no previous release to bump from: the
# version sitting in regexlib.h *is* the release. (abidiff has nothing to
# compare against either, and skips itself.)
if [ -z "$(git tag --list 'v*')" ]; then
  if [ "$FORCE_MINOR" -eq 1 ] || [ "$FORCE_MAJOR" -eq 1 ]; then
    echo ""
    echo "Error: no release tag exists yet, so there is nothing to bump."
    echo "       Edit REGEXLIB_VERSION / REGEXLIB_VERSION_NUM in regexlib.h to"
    echo "       pick the initial version, then run without --minor/--major."
    exit 1
  fi

  echo ""
  echo "==> No release tag found → initial release of v$CURRENT_VERSION"
  echo ""
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "==> [DRY RUN] Would tag v$CURRENT_VERSION at $HEAD_SHORT and push."
    echo ""
    echo "==> Dry run complete. No changes were made."
  else
    tag_and_push "$CURRENT_VERSION" "git tag -d v$CURRENT_VERSION"
  fi
  exit 0
fi

if [ "$FORCE_MAJOR" -eq 1 ]; then
  NEW_MAJOR=$((V_MAJOR + 1))
  NEW_VERSION="$NEW_MAJOR.0.0"
  echo ""
  echo "==> --major specified → forced major bump"
elif [ "$FORCE_MINOR" -eq 1 ]; then
  NEW_MINOR=$((V_MINOR + 1))
  NEW_VERSION="$V_MAJOR.$NEW_MINOR.0"
  echo ""
  if [ "$ABIDIFF_PASSED" -eq 1 ]; then
    echo "==> abidiff passed but --minor specified → forced minor bump"
  else
    echo "==> abidiff failed → minor bump (--minor also specified)"
  fi
elif [ "$ABIDIFF_PASSED" -eq 1 ]; then
  NEW_PATCH=$((V_PATCH + 1))
  NEW_VERSION="$V_MAJOR.$V_MINOR.$NEW_PATCH"
  echo ""
  echo "==> abidiff passed → patch bump"
else
  NEW_MINOR=$((V_MINOR + 1))
  NEW_VERSION="$V_MAJOR.$NEW_MINOR.0"
  echo ""
  echo "==> abidiff failed → minor bump"
fi

VERSION_HEX=$(version_hex "$NEW_VERSION")

if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> [DRY RUN] New version: $NEW_VERSION ($VERSION_HEX)"
else
  echo "==> New version: $NEW_VERSION ($VERSION_HEX)"
fi

# --- Step 5: Update files ---
# regexlib.h is the single source of truth: CMakeLists.txt reads the project
# version straight out of REGEXLIB_VERSION, so there is nothing else to bump.
echo ""
if [ "$DRY_RUN" -eq 1 ]; then
  echo "==> [DRY RUN] Would update regexlib.h:"
  echo "    REGEXLIB_VERSION     = \"$NEW_VERSION\""
  echo "    REGEXLIB_VERSION_NUM = $VERSION_HEX"
  echo ""
  echo "==> [DRY RUN] Would commit, tag v$NEW_VERSION, and push."
  echo ""
  echo "==> Dry run complete. No changes were made."
else
  echo "==> Updating regexlib.h..."
  sed -i '' "s/#define REGEXLIB_VERSION \"[^\"]*\"/#define REGEXLIB_VERSION \"$NEW_VERSION\"/" regexlib.h
  sed -i '' "s/#define REGEXLIB_VERSION_NUM 0x[0-9a-fA-F]*/#define REGEXLIB_VERSION_NUM $VERSION_HEX/" regexlib.h
  echo "    REGEXLIB_VERSION     = \"$NEW_VERSION\""
  echo "    REGEXLIB_VERSION_NUM = $VERSION_HEX"

  # --- Step 6: Commit, tag, and push ---
  echo ""
  echo "==> Committing..."
  git add regexlib.h
  git commit -m "Release v$NEW_VERSION"

  echo ""
  tag_and_push "$NEW_VERSION" "git reset --hard HEAD~1 && git tag -d v$NEW_VERSION"
fi
