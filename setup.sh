#!/bin/sh
# 設定精靈（在 VM 上執行）：建立/選擇測試帳號、選擇業務服務、檢查套件庫、寫入 config.ini、健康檢查
# 用法：sudo ./setup.sh
#       sudo ./setup.sh --user gcbtest --services nginx,postgresql   （不詢問，直接指定）
DIR=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" != "0" ]; then
    exec sudo "$DIR/setup.sh" "$@"
fi
exec "$DIR/gcb.sh" setup "$@"
