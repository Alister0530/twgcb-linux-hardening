#!/bin/sh
# 在你的電腦上執行（macOS / Linux），透過 SSH 部署到 VM 或取回報告。
#
# 用法：
#   ./deploy.sh 帳號@VM的IP           打包 → 上傳 → 安裝到 /opt/gcb-checker → 啟動設定精靈
#   ./deploy.sh 帳號@VM的IP fetch     取回 VM 上的報告與 log（不含備份檔）到 ./vm-reports/
#
# 重新部署時會保留 VM 上原本的 config.ini 與 reports/。
# SSH 非 22 埠或需指定金鑰時，用 SSH_OPTS 傳入，例如：
#   SSH_OPTS="-o Port=2222 -i ~/.ssh/vm_key" ./deploy.sh 帳號@VM的IP
set -e

# 在 VM 以登入帳號建立暫存目錄；SSH 連線失敗與建立失敗分開提示
remote_tmp() {
    if ! out=$(ssh $SSH_OPTS "$TARGET" "mktemp -d /tmp/$1.XXXXXX"); then
        echo "無法連線 VM（$TARGET）。請確認：" >&2
        echo "  - 帳號、密碼是否正確" >&2
        echo "  - 密碼是否在 60 秒內輸入（GCB 修復後 SSH 登入等待時間縮短為 60 秒）" >&2
        echo "  - 連續輸錯會累計失敗次數，稍候再試；仍失敗請先用 ssh $TARGET 互動登入確認" >&2
        exit 1
    fi
    out=$(printf "%s" "$out" | tr -d '\r')
    [ -n "$out" ] || { echo "已連線 VM，但無法建立暫存目錄（/tmp 空間或權限問題）" >&2; exit 1; }
    printf "%s" "$out"
}

TARGET=$1
MODE=${2:-deploy}
if [ -z "$TARGET" ]; then
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

DIR=$(cd "$(dirname "$0")" && pwd)
NAME=$(basename "$DIR")
REMOTE=/opt/gcb-checker

case "$MODE" in
deploy)
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    echo "[1/3] 打包..."
    # macOS 的 tar 會帶入 Mac 專屬屬性，VM 解壓時會出現大量警告，先排除
    TAR_OPTS=""
    if tar --version 2>/dev/null | grep -q bsdtar; then
        TAR_OPTS="--no-xattrs --no-mac-metadata"
    fi
    # COPYFILE_DISABLE：避免 macOS 在壓縮檔中加入 ._ 檔案
    COPYFILE_DISABLE=1 tar czf "$TMP/gcb-checker.tar.gz" $TAR_OPTS -C "$(dirname "$DIR")" \
        --exclude=docs --exclude=tools --exclude=samples --exclude=tests --exclude=reports --exclude=vm-reports \
        --exclude=__pycache__ --exclude='*.tar.gz' --exclude='.DS_Store' --exclude=.idea "$NAME"

    # 遠端暫存目錄由一般帳號以 mktemp 建立（權限 700、名稱隨機），避免固定路徑被搶先建立或替換
    RD=$(remote_tmp gcb-deploy)
    echo "[2/3] 上傳到 $TARGET ..."
    scp -q $SSH_OPTS "$TMP/gcb-checker.tar.gz" "$TARGET:$RD/gcb-checker.tar.gz"

    echo "[3/3] 安裝到 $REMOTE 並啟動設定精靈（可能會詢問 sudo 密碼）"
    ssh -t $SSH_OPTS "$TARGET" "sudo sh -c '
        set -e
        KEEP=
        [ -f $REMOTE/config.ini ] && KEEP=--exclude=config.ini   # 保留原本的設定檔
        mkdir -p $REMOTE
        tar xzf $RD/gcb-checker.tar.gz -C $REMOTE --strip-components=1 \$KEEP
        chown -R root:root $REMOTE
        chmod 755 $REMOTE/gcb.sh $REMOTE/setup.sh
        cd $REMOTE
        if grep -Eq \"^test_user *= *\\\$\" config.ini; then
            ./setup.sh
        else
            echo
            echo \"已安裝。config.ini 已有設定（test_user 已填寫），略過設定精靈。\"
            echo \"若要重新設定：cd $REMOTE && sudo ./setup.sh\"
        fi
    '; rm -rf $RD"
    ;;
fetch)
    HOST=$(echo "$TARGET" | sed 's/.*@//')
    OUT="$DIR/vm-reports/${HOST}_$(date +%Y%m%d_%H%M%S)"
    RD=$(remote_tmp gcb-fetch)
    echo "[1/3] 在 VM 上打包報告（不含 backup/ 備份檔）..."
    # 打包到自己的暫存目錄（權限 700），並把壓縮檔交給登入帳號，下載後可自行刪除
    ssh -t $SSH_OPTS "$TARGET" "sudo sh -c '
        cd $REMOTE && tar czf $RD/reports.tar.gz --exclude=backup --exclude=rollback.json reports
        chown \$SUDO_UID $RD/reports.tar.gz && chmod 600 $RD/reports.tar.gz
    '"
    echo "[2/3] 下載..."
    mkdir -p "$OUT"
    scp -q $SSH_OPTS "$TARGET:$RD/reports.tar.gz" "$OUT/reports.tar.gz"
    ssh $SSH_OPTS "$TARGET" "rm -rf $RD" || echo "提醒：請手動刪除 VM 上的 $RD"
    echo "[3/3] 解壓縮..."
    tar xzf "$OUT/reports.tar.gz" -C "$OUT" && rm "$OUT/reports.tar.gz"
    echo
    echo "報告已下載到：$OUT/reports"
    find "$OUT" -name 'GCB*.xlsx' | sed 's/^/  /'
    ;;
*)
    echo "未知的模式：$MODE（可用 deploy 或 fetch）"
    exit 1
    ;;
esac
