#!/usr/bin/env bash
# Looks for secrets and real server details before they reach the repo.
#
#   scripts/check-secrets.sh            files staged for commit
#   scripts/check-secrets.sh --all      every tracked file
#   scripts/check-secrets.sh --history  every commit, plus authors and messages
#
# SECRET_SCAN_DENYLIST may point to a file with extra strings to block, one per
# line (your real hostnames, IPs, names). Keep that file outside the repo.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

mode=${1:---staged}
case $mode in
  --staged)
    revs=(--cached)
    files=$(git ls-files --cached)
    ;;
  --all)
    revs=()
    files=$(git ls-files)
    ;;
  --history)
    mapfile -t revs < <(git rev-list --all)
    files=$(git log --all --format= --name-only | sort -u)
    ;;
  *)
    echo "usage: $0 [--staged | --all | --history]" >&2
    exit 2
    ;;
esac

problems=0
self=':(exclude)scripts/check-secrets.sh'

flag() {
  printf '\n[%s]\n%s\n' "$1" "$2"
  problems=1
}

# check NAME REGEX [ALLOWED]: flags matches of REGEX, except lines matching ALLOWED.
# Output lines look like "path:line:match" (or "commit:path:line:match").
check() {
  local name=$1 regex=$2 allowed=${3:-} hits
  hits=$(git grep -I -n -o -i -E -e "$regex" "${revs[@]}" -- . "$self" 2>/dev/null || true)
  if [[ -n $hits && -n $allowed ]]; then
    hits=$(grep -v -i -E -e "$allowed" <<<"$hits" || true)
  fi
  if [[ -n $hits ]]; then flag "$name" "$hits"; fi
}

if [[ ${#revs[@]} -eq 0 && $mode == --history ]]; then
  echo "no commits yet"
  exit 0
fi

check "private key" \
  '-----BEGIN [A-Z ]*PRIVATE KEY-----|PuTTY-User-Key-File'

check "token" \
  'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|(sk|rk)_live_[A-Za-z0-9]{10,}|whsec_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}'

check "IPv4 address" \
  '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  ':(127\.[0-9.]+|0\.0\.0\.0|10\.[0-9.]+|192\.168\.[0-9.]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9.]+|192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+|255\.255\.255\.[0-9]+)$'

check "IPv6 address" \
  '(2[0-9a-f]{3}|fe80)(:[0-9a-f]{0,4}){4,7}' \
  ':2001:0?db8:'

# The TLD must end the word, so code like `tx.commit` is not read as a domain.
check "domain" \
  '[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|org|eu|io|bg|de|uk|info|me|xyz)([^a-z0-9-]|$)' \
  ':(.*\.)?(example\.(com|net|org)|github\.com|githubusercontent\.com|crates\.io|docs\.rs|rust-lang\.org|db-ip\.com|cloudflare\.com|htmx\.org|sqlite\.org|nginx\.org|letsencrypt\.org|opensource\.org|freedesktop\.org|shields\.io|semver\.org)[^a-z0-9-]?$'

check "email address" \
  '[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}' \
  '@(users\.noreply\.github\.com|github\.com|example\.(com|net|org))$'

check "home directory" \
  '/home/[a-z0-9_.-]+|[a-z]:\\users\\[a-z0-9_.-]+|/users/[a-z0-9_.-]+'

if [[ -n ${SECRET_SCAN_DENYLIST:-} ]]; then
  [[ -r $SECRET_SCAN_DENYLIST ]] || { echo "cannot read $SECRET_SCAN_DENYLIST" >&2; exit 2; }
  deny=()
  while IFS= read -r line; do
    line=${line%$'\r'}
    [[ -z ${line// } || $line == \#* ]] && continue
    deny+=(-e "$line")
  done <"$SECRET_SCAN_DENYLIST"
  if [[ ${#deny[@]} -gt 0 ]]; then
    hits=$(git grep -I -n -o -i -F "${deny[@]}" "${revs[@]}" -- . 2>/dev/null || true)
    if [[ -n $hits ]]; then flag "denylist" "$hits"; fi
    if [[ $mode == --history ]]; then
      hits=$(git log --all --format=%B | grep -n -i -F "${deny[@]}" || true)
      if [[ -n $hits ]]; then flag "denylist in commit messages" "$hits"; fi
    fi
  fi
fi

bad_files=$(grep -i -E '(^|/)(\.env(\..*)?|config\.toml|.*\.(db|db-wal|db-shm|sqlite3?|mmdb|pem|key|p12|pfx)|id_(rsa|ecdsa|ed25519)(\.pub)?|.*deploy_key.*)$' <<<"$files" || true)
if [[ -n $bad_files ]]; then flag "file that must not be committed" "$bad_files"; fi

if [[ $mode == --history ]]; then
  authors=$(git log --all --format='%an <%ae>%n%cn <%ce>' | sort -u)
  others=$(grep -v -x -E '[^<]+ <[0-9]+\+[A-Za-z0-9-]+@users\.noreply\.github\.com>|GitHub <noreply@github\.com>' <<<"$authors" || true)
  if [[ -n $others ]]; then flag "author or committer without a noreply address" "$others"; fi

  attribution=$(git log --all --format='%h %B' | grep -i -E 'co-authored-by|generated (with|by)' || true)
  if [[ -n $attribution ]]; then flag "attribution line in commit message" "$attribution"; fi
fi

echo "scanned $(grep -c . <<<"$files") files ($mode)"
if [[ $problems -ne 0 ]]; then
  echo "secret check: problems found"
  exit 1
fi
echo "secret check: nothing found"
