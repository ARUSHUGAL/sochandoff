#!/bin/sh
# Install the soc-shift-handoff agent skill for Claude Code, Codex, Kiro and Freebuff.
#
#   curl -fsSL https://raw.githubusercontent.com/ARUSHUGAL/sochandoff/main/install-skill.sh | sh
#   curl -fsSL .../install-skill.sh | sh -s -- --agent claude --agent kiro
#   sh install-skill.sh --project          # into ./.agents, ./.claude, ./.kiro of this repo
#   sh install-skill.sh --with-cli         # also pip-install the sochandoff CLI
#
# One master copy lives in ~/.local/share/sochandoff-skill; each agent folder gets
# a symlink to it, so an update fixes every agent at once. Existing folders that
# are not ours are left alone.
set -eu

SKILL=soc-shift-handoff
TARBALL="https://github.com/ARUSHUGAL/sochandoff/archive/refs/heads/main.tar.gz"
MASTER="${XDG_DATA_HOME:-$HOME/.local/share}/sochandoff-skill"

agents=""
scope=user
copy=0
with_cli=0
while [ $# -gt 0 ]; do
  case "$1" in
    --agent) agents="$agents $2"; shift 2 ;;
    --project) scope=project; shift ;;
    --copy) copy=1; shift ;;
    --with-cli) with_cli=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done
[ -n "$agents" ] || agents="claude codex kiro freebuff"

# 1. Get the master copy: from this checkout if we are in one, else download.
here=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")
mkdir -p "$MASTER"
if [ -n "$here" ] && [ -f "$here/skills/$SKILL/SKILL.md" ]; then
  src="$here/skills/$SKILL"
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "$TARBALL" | tar -xz -C "$tmp"
  src="$tmp/sochandoff-main/skills/$SKILL"
fi
rm -rf "$MASTER/$SKILL"
cp -R "$src" "$MASTER/$SKILL"
chmod +x "$MASTER/$SKILL/scripts/"*.sh 2>/dev/null || true
echo "skill saved to $MASTER/$SKILL"

# 2. Point each agent at it.
if [ "$scope" = project ]; then base=$(pwd); else base=$HOME; fi
dir_for() {
  case "$1" in
    claude)          echo "$base/.claude/skills" ;;
    codex|freebuff)  echo "$base/.agents/skills" ;;   # both read .agents/skills
    kiro)            echo "$base/.kiro/skills" ;;
    *) echo "" ;;
  esac
}

done_dirs=""
for a in $agents; do
  d=$(dir_for "$a")
  if [ -z "$d" ]; then echo "  skip $a: unknown agent (use claude, codex, kiro, freebuff)"; continue; fi
  case " $done_dirs " in *" $d "*) echo "  $a: uses $d (done)"; continue ;; esac
  done_dirs="$done_dirs $d"
  mkdir -p "$d"
  target="$d/$SKILL"
  if [ -e "$target" ] && [ ! -L "$target" ]; then
    echo "  skip $a: $target exists and is not ours. Remove it to reinstall."
    continue
  fi
  rm -f "$target"
  if [ "$copy" = 1 ]; then cp -R "$MASTER/$SKILL" "$target"; else ln -s "$MASTER/$SKILL" "$target"; fi
  echo "  $a: $target"
done

# 3. Optional: the CLI the skill drives.
if [ "$with_cli" = 1 ]; then
  if command -v pipx >/dev/null 2>&1; then
    pipx install --force "git+https://github.com/ARUSHUGAL/sochandoff.git"
  else
    python3 -m pip install --user "git+https://github.com/ARUSHUGAL/sochandoff.git"
  fi
fi

command -v sochandoff >/dev/null 2>&1 || echo "note: the skill needs the CLI. Re-run with --with-cli, or: pip install git+https://github.com/ARUSHUGAL/sochandoff.git"
echo "done. Restart your agent, then ask it: \"do my shift handoff\""
echo "undo: rm -rf $MASTER and the symlinks listed above"
