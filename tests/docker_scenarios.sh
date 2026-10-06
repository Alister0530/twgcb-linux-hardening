#!/bin/sh
# 容器情境測試：依操作手冊的指令順序，用真實規則驗證各指令（docker_test.sh 只測完整修復與回滾）。
#   setup.sh（參數模式）→ health → rules → list → check → run --dry-run（/etc 不得變動）
#   → run（只修 A 類）→ rollback --rule（只還原單一規則）→ verify → rollback（整次）
# 用法：tests/docker_scenarios.sh ubuntu:22.04
#       PLATFORM=linux/amd64 tests/docker_scenarios.sh rockylinux:9
set -e
IMG=${1:-ubuntu:22.04}
SRC=$(cd "$(dirname "$0")/.." && pwd)
PLAT=${PLATFORM:+--platform $PLATFORM}

docker run --rm $PLAT ${COV_DIR:+-v "$COV_DIR":/cov} -v "$SRC":/src:ro "$IMG" sh -c '
set -e
if command -v dnf >/dev/null; then
  dnf -q -y install openssh-server openssh-clients procps-ng passwd sudo authselect iproute util-linux findutils diffutils >/dev/null
  authselect select sssd --force >/dev/null 2>&1 || true
  GROUP=wheel
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update && apt-get -qq -y install python3 openssh-server openssh-client procps sudo iproute2 diffutils >/dev/null
  GROUP=sudo
fi
ssh-keygen -A >/dev/null; mkdir -p /run/sshd; /usr/sbin/sshd
useradd -m -s /bin/bash gcbtest && usermod -aG $GROUP gcbtest
cp -r /src /opt/gcb && cd /opt/gcb && rm -rf reports tests/out
[ -d /cov ] && printf "%s\n" "#!/bin/sh" "for PY in python3 /usr/libexec/platform-python; do command -v \$PY >/dev/null && exec \$PY /opt/gcb/tools/coverage.py trace /opt/gcb/gcb.py \"\$@\"; done" > gcb.sh  # COV_DIR：量測涵蓋率
PY=$(command -v python3 || echo /usr/libexec/platform-python)
PASS=0; FAIL=0
ok()  { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }
snap() { find /etc -type f -newer /tmp/mark 2>/dev/null | grep -v -E "^/etc/(ld.so.cache|machine-id)" | sort; }
last_run() { ls -t reports | grep -v -E "^(check|health|setup)_" | head -1; }

echo "== setup.sh（參數模式）"
./setup.sh --user gcbtest --services "" > /tmp/setup.txt 2>&1 || true
grep -q "^test_user = gcbtest" config.ini && ok "config.ini 已寫入 test_user" || bad "config.ini 未寫入 test_user"

echo "== health / rules / list"
./gcb.sh health > /tmp/h.txt 2>&1 && grep -q "H04" /tmp/h.txt && ok "health 輸出健康檢查" || bad "health 失敗"
N=$(./gcb.sh rules | grep -c "^TWGCB-01-[0-9]*-[0-9]") ; [ "$N" -gt 0 ] && ok "rules 列出 $N 條" || bad "rules 沒有輸出"
./gcb.sh list | grep -q "health_" && ok "list 列出執行紀錄" || bad "list 沒有紀錄"

echo "== check"
./gcb.sh check > /tmp/c.txt 2>&1 && ls reports/check_*/GCB不合格清單_*.xlsx >/dev/null 2>&1 && ok "check 產出不合格清單" || bad "check 失敗"

echo "== run --dry-run（不得修改 /etc）"
touch /tmp/mark; sleep 1
./gcb.sh run --dry-run --include-risky --force > /tmp/d.txt 2>&1 || true
CHANGED=$(snap)
[ -z "$CHANGED" ] && ok "預覽後 /etc 沒有任何檔案變動" || { bad "預覽修改了檔案："; echo "$CHANGED" | head; }
grep -q "預覽完成" /tmp/d.txt && ok "預覽完成並產出報告" || bad "預覽沒有完成"
grep -q "Traceback" /tmp/d.txt && bad "預覽出現 Traceback" || ok "預覽沒有程式錯誤"

echo "== run（只修 A 類）"
./gcb.sh run -y --force --no-manual-confirm > /tmp/r.txt 2>&1 || true
RID=$(last_run)
grep -q "Traceback\|檢測程式錯誤" /tmp/r.txt && bad "run 出現程式錯誤" || ok "run 沒有程式錯誤"
$PY - "$RID" <<PY && ok "只修 A 類：B、C 類都沒有被修復" || bad "B 或 C 類被修復了"
import json, sys
st = json.load(open("reports/%s/state.json" % sys.argv[1]))
done = [f for f in st["fixes"] if f["outcome"].startswith(("已修復", "部分修復", "修復失敗"))]
sys.exit(1 if [f for f in done if not f["risk_label"].startswith("A")] else 0)
PY

echo "== rollback --rule（只還原單一規則）"
RULE=$($PY - "$RID" <<PY
import json, sys
j = json.load(open("reports/%s/rollback.json" % sys.argv[1]))
st = json.load(open("reports/%s/state.json" % sys.argv[1]))
fixed = {f["id"] for f in st["fixes"] if f["outcome"].startswith("已修復")}
rules = [e["rule"] for e in j if e["type"] == "file" and not e["rolled_back"] and e["rule"] in fixed]
print(rules[0] if rules else "")
PY
)
if [ -n "$RULE" ]; then
  cp "reports/$RID/rollback.json" /tmp/rb_before.json
  ./gcb.sh rollback "$RID" --rule "$RULE" > /tmp/rr.txt 2>&1 || true
  $PY - "$RID" "$RULE" <<PY && ok "rollback --rule $RULE 只回滾該規則" || bad "rollback --rule 範圍不正確"
import json, sys
before = {e["seq"]: e["rolled_back"] for e in json.load(open("/tmp/rb_before.json"))}
after = json.load(open("reports/%s/rollback.json" % sys.argv[1]))
changed = [e for e in after if e["rolled_back"] != before.get(e["seq"])]
mine = [e for e in after if e["rule"] == sys.argv[2]]
sys.exit(0 if mine and all(e["rolled_back"] for e in mine) and all(e["rule"] == sys.argv[2] for e in changed) else 1)
PY
else
  bad "找不到可測試的已修復規則"
fi

echo "== verify"
./gcb.sh verify "$RID" > /tmp/v.txt 2>&1 && grep -q "已更新修復情況報告" /tmp/v.txt && ok "verify 更新修復報告" || bad "verify 失敗"
$PY -c "import json,sys; st=json.load(open(\"reports/$RID/state.json\")); sys.exit(0 if len(st[\"verify\"])==1 else 1)" && ok "verify 結果已寫入" || bad "verify 結果未寫入"

echo "== rollback（整次）"
./gcb.sh rollback "$RID" > /tmp/ra.txt 2>&1 && ok "整次回滾完成" || bad "整次回滾失敗"
$PY - "$RID" <<PY && ok "所有檔案類修改都已回滾" || bad "仍有檔案類修改未回滾"
import json, sys
j = json.load(open("reports/%s/rollback.json" % sys.argv[1]))
sys.exit(0 if all(e["rolled_back"] for e in j if e["type"] in ("file", "meta", "dir")) else 1)
PY

echo "== 結果：通過 $PASS 項，失敗 $FAIL 項"
[ "$FAIL" -eq 0 ]
'
