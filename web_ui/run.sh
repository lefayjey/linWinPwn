#!/bin/bash
# linWinPwn Web UI launcher
# Usage: ./web_ui/run.sh [--host 127.0.0.1] [--port 8777]
set -e
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
VENV="${HERE}/.venv"

if [ ! -d "${VENV}" ]; then
  echo "[*] Creating virtualenv in ${VENV}"
  python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install --quiet --upgrade pip
  "${VENV}/bin/pip" install --quiet -r "${HERE}/requirements.txt"
fi

# Generate an auth token unless one is already set (recommended for anything
# beyond pure localhost use).
if [ -z "${LWP_WEB_TOKEN}" ]; then
  if [ "$1" == "--no-token" ]; then shift;
  else
    export LWP_WEB_TOKEN="$(openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | xxd -p)"
    echo "[*] Generated auth token. Open the UI with:"
    echo "    http://127.0.0.1:8777/?token=${LWP_WEB_TOKEN}"
  fi
fi

exec "${VENV}/bin/python" "${HERE}/server.py" "$@"
