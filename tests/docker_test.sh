#!/bin/sh
# 在容器內做流程測試：check → run → rollback，並比對 /etc 是否完整還原。
# 容器沒有 systemd / GRUB，只能驗證檢測、修復、回滾與報告流程，不能取代 VM 測試。
# 用法：tests/docker_test.sh rockylinux:9
#       PLATFORM=linux/amd64 tests/docker_test.sh rockylinux:9   （指定 CPU 架構，例如在 ARM 主機測 x86_64）
# COV_DIR=$PWD/tests/out/cov 時一併量測涵蓋率（見 tools/coverage.py）
set -e
IMG=${1:-rockylinux:9}
SRC=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-"$SRC/tests/out/$(echo "$IMG${PLATFORM:+_$PLATFORM}" | tr ':/' '__')"}
rm -rf "$OUT" && mkdir -p "$OUT"

docker run --rm ${PLATFORM:+--platform $PLATFORM} ${COV_DIR:+-v "$COV_DIR":/cov} -v "$SRC":/src:ro -v "$OUT":/out "$IMG" sh -c '
set -e
if command -v dnf >/dev/null; then
  dnf -q -y install openssh-server openssh-clients telnet procps-ng passwd sudo authselect libpwquality iproute util-linux findutils diffutils >/dev/null
  authselect select sssd --force >/dev/null 2>&1 || true
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get -qq update && apt-get -qq -y install python3 openssh-server openssh-client telnet procps sudo iproute2 diffutils >/dev/null
fi
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
useradd -m gcbtest && echo "gcbtest ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/gcbtest && chmod 440 /etc/sudoers.d/gcbtest
echo "PermitRootLogin yes" > /etc/ssh/sshd_config.d/01-test.conf 2>/dev/null || true
/usr/sbin/sshd
cp -r /src /opt/gcb && cd /opt/gcb && rm -rf reports tests/out
[ -d /cov ] && printf "%s\n" "#!/bin/sh" "for PY in python3 /usr/libexec/platform-python; do command -v \$PY >/dev/null && exec \$PY /opt/gcb/tools/coverage.py trace /opt/gcb/gcb.py \"\$@\"; done" > gcb.sh  # COV_DIR：量測涵蓋率
sed -i "s/^test_user =.*/test_user = gcbtest/" config.ini
cp -a /etc /tmp/etc.before

echo "===== check"; ./gcb.sh check | tail -3
echo "===== run"; ./gcb.sh run --include-risky --force -y --no-manual-confirm || true
RID=$(ls -t reports | grep -v ^check_ | head -1)
echo "===== 修復後 PAM auth 設定"; grep -h -E "^auth" /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null || true
echo "===== rollback $RID"; ./gcb.sh rollback "$RID" | head -40
echo "===== /etc 差異（應只有 ld.so.cache / 套件相關）"
diff -rq /tmp/etc.before /etc 2>&1 | grep -v -E "ld.so.cache|alternatives|/etc/(group|gshadow|passwd|shadow)-$" || echo "（無差異）"
cp -r reports /out/
'
echo "報告已複製到 $OUT/reports"
