#!/bin/sh
# 啟動腳本：尋找可用的 Python 3（RHEL 8 最小安裝只有 platform-python）
DIR=$(cd "$(dirname "$0")" && pwd)
for PY in python3 /usr/libexec/platform-python; do
    if command -v "$PY" >/dev/null 2>&1; then
        exec "$PY" "$DIR/gcb.py" "$@"
    fi
done
echo "找不到 Python 3，請安裝 python3" >&2
exit 1
