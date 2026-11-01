#!/bin/sh
# Start a local TheHive 5 lab and fill it with test cases.
#   sh lab/run-lab.sh          start + seed
#   sh lab/run-lab.sh stop     stop the lab (keeps data)
#   sh lab/run-lab.sh destroy  stop and delete lab data
set -eu
cd "$(dirname "$0")/thehive"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1. Run: brew install colima docker docker-compose" >&2; exit 1; }; }
need colima; need docker

compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi
}

case "${1:-start}" in
  stop)    compose stop; colima stop; exit 0 ;;
  destroy) compose down -v; colima stop; exit 0 ;;
esac

if ! colima status >/dev/null 2>&1; then
  echo "starting colima (2 CPU, 4 GB RAM)..."
  colima start --cpu 2 --memory 4 --disk 20
fi

compose up -d
python3 ../thehive/seed.py
echo ""
echo "TheHive UI: http://127.0.0.1:9000  (admin@thehive.local / secret)"
echo "Try:  . ~/.sochandoff/lab.env && sochandoff --from thehive"
echo "Stop: sh lab/run-lab.sh stop"
