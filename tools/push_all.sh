#!/bin/sh
# 推送到兩個遠端，各自保有自己的歷史，不需強制推送：
#   1. 本專案（gcb-checker）→ GitLab：git push gitlab main
#   2. 版本控制內的檔案同步到公開版資料夾（預設 ../gcb-checker-public）→ 檢查 → 測試 → commit → GitHub
#      公開版的 commit 作者使用該資料夾的 git 設定（個人帳號）；GCB 官方 PDF 與 chunks.json 不在版本控制內，不會同步
# 用法：tools/push_all.sh [--dry-run]
#   PUBLIC_DIR=<路徑> 指定公開版資料夾；SYNC_FROM=<commit> 指定說明要列出的起點（預設為上次同步的 commit）
set -e
cd "$(dirname "$0")/.."
SRC=$(pwd)
PUB=${PUBLIC_DIR:-"$SRC/../gcb-checker-public"}
DRY=; [ "$1" = "--dry-run" ] && DRY=1
# 不可出現在公開 repo 的字串（公司網域）；本檔案除外
BLOCK='iptcloud\.net|bronci\.com'

[ -z "$(git status --porcelain)" ] || { echo "有尚未 commit 的修改，請先 commit"; exit 1; }
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || { echo "請在 main 分支執行"; exit 1; }
[ -d "$PUB/.git" ] || { echo "找不到公開版資料夾：$PUB（可用 PUBLIC_DIR 指定）"; exit 1; }
[ -z "$(git -C "$PUB" status --porcelain)" ] || { echo "公開版資料夾有未 commit 的修改：$PUB"; exit 1; }

echo "== 1/3 GitLab"
if [ -n "$DRY" ]; then git push --dry-run gitlab main; else git push gitlab main; fi

echo "== 2/3 同步到公開版（$PUB）"
LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT
git -c core.quotepath=false ls-files > "$LIST"
# 刪除：公開版有、本專案已不存在的檔案
git -C "$PUB" -c core.quotepath=false ls-files | sort > "$LIST.pub"
sort "$LIST" | comm -23 "$LIST.pub" - | while IFS= read -r f; do git -C "$PUB" rm -q -- "$f"; done
rm -f "$LIST.pub"
rsync -a --files-from="$LIST" ./ "$PUB/"
git -C "$PUB" add -A
if git -C "$PUB" diff --cached --quiet; then
    echo "  公開版已是最新，不需推送"
    exit 0
fi

echo "  檢查公開內容"
BAD=$(git -C "$PUB" -c core.quotepath=false diff --cached --name-only | grep -E '^docs/gcb/.*(\.pdf|chunks\.json)$' || true)
HIT=$(git -C "$PUB" grep --cached -I -l -E "$BLOCK" -- . ':!tools/push_all.sh' || true)
# 說明要列出的 commit：上次同步之後（公開版最後一個 commit 的 Source-Commit）到目前
LAST=${SYNC_FROM:-$(git -C "$PUB" log -1 --format=%B | sed -n 's/^Source-Commit: //p')}
RANGE=${LAST:+$LAST..}HEAD
SUBJECTS=$(git log --reverse --format='- %s' $RANGE | grep -v '^- *$' || true)
[ -n "$LAST" ] || SUBJECTS=$(git log -1 --format='- %s')
MSG=$(printf '同步更新\n\n%s\n\nSource-Commit: %s\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n' \
    "$SUBJECTS" "$(git rev-parse --short HEAD)")
if [ -n "$BAD$HIT" ] || printf '%s' "$MSG" | grep -qE "$BLOCK"; then
    echo "  含不可公開的內容，已中止並還原公開版資料夾："
    [ -n "$BAD" ] && echo "$BAD"
    [ -n "$HIT" ] && echo "$HIT"
    git -C "$PUB" reset -q --hard HEAD
    exit 1
fi
echo "  通過"
echo "  執行單元測試"
(cd "$PUB" && python3 -m unittest discover -s tests >/dev/null 2>&1) || {
    echo "  公開版單元測試失敗，已中止並還原公開版資料夾"; git -C "$PUB" reset -q --hard HEAD; exit 1; }
echo "  通過"

echo "== 3/3 GitHub"
git -C "$PUB" diff --cached --stat | tail -1
if [ -n "$DRY" ]; then
    echo "  （預覽：公開版資料夾已還原，未 commit、未推送）"
    printf '%s\n' "$MSG" | sed 's/^/  | /'
    git -C "$PUB" reset -q --hard HEAD
else
    printf '%s\n' "$MSG" | git -C "$PUB" commit -q -F -
    git -C "$PUB" push origin main
fi
