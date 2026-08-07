#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Verify that an ordinary-user vmspawn --bind reaches the guest without a userns mapping.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ -v ASAN_OPTIONS ]]; then
    echo "vmspawn launches QEMU which does not work under ASan, skipping"
    exit 0
fi

if ! command -v systemd-vmspawn >/dev/null 2>&1; then
    echo "systemd-vmspawn not found, skipping"
    exit 0
fi

if ! find_qemu_binary; then
    echo "QEMU not found, skipping"
    exit 0
fi

if ! command -v virtiofsd >/dev/null 2>&1 &&
   ! test -x /usr/libexec/virtiofsd &&
   ! test -x /usr/lib/virtiofsd; then
    echo "virtiofsd not found, skipping"
    exit 0
fi

if ! command -v mke2fs >/dev/null 2>&1; then
    echo "mke2fs not found, skipping"
    exit 0
fi

if ! id testuser >/dev/null 2>&1; then
    echo "testuser not found, skipping"
    exit 0
fi

GUEST_TEMPLATE=/usr/share/TEST-13-NSPAWN-container-template
if [[ ! -d "$GUEST_TEMPLATE" ]] || ! runas testuser test -r "$GUEST_TEMPLATE/usr/bin/bash"; then
    echo "Minimal guest template not available to testuser, skipping"
    exit 0
fi

KERNEL=""
for k in /usr/lib/modules/"$(uname -r)"/vmlinuz /boot/vmlinuz-"$(uname -r)" /boot/vmlinuz; do
    if [[ -f "$k" ]] && runas testuser test -r "$k"; then
        KERNEL="$k"
        break
    fi
done

if [[ -z "$KERNEL" ]]; then
    echo "No testuser-readable kernel found for direct VM boot, skipping"
    exit 0
fi

TEST_UID="$(id -u testuser)"
MACHINE="test-vmspawn-user-bind-$$"
WORKDIR="$(mktemp -d /tmp/test-vmspawn-user-bind.XXXXXXXXXX)"
SHARE="$WORKDIR/share"
IMAGE="$WORKDIR/root.raw"
LOG="$WORKDIR/vmspawn.log"

at_exit() {
    set +e

    pkill -TERM -f "${MACHINE}" 2>/dev/null
    sleep 0.2
    pkill -KILL -f "${MACHINE}" 2>/dev/null

    rm -rf "$WORKDIR"
    loginctl disable-linger testuser 2>/dev/null
}
trap at_exit EXIT

loginctl enable-linger testuser
systemctl start "user@${TEST_UID}.service"

chown testuser:testuser "$WORKDIR"

# Match the existing TEST-87 vmspawn disk-image pattern: make a plain ext4
# filesystem image populated from systemd's minimal test root and boot it as
# /dev/vda with the current test kernel.
truncate -s 768M "$IMAGE"
mke2fs -t ext4 -q -d "$GUEST_TEMPLATE" "$IMAGE"
chown testuser:testuser "$IMAGE"

runas testuser mkdir "$SHARE"
runas testuser sh -c "printf '%s\n' vmspawn-user-bind-ok >'$SHARE/host-probe'"
runas testuser tee "$SHARE/guest-probe.sh" >/dev/null <<EOF
#!/usr/bin/bash
set -eux
read -r probe < "$SHARE/host-probe"
test "\$probe" = vmspawn-user-bind-ok
printf '%s\n' vmspawn-guest-ok > "$SHARE/guest-probe"
EOF
runas testuser chmod +x "$SHARE/guest-probe.sh"

# systemd.run= is Type=oneshot with SuccessAction=exit by default. Executing a
# script directly from the virtiofs bind proves guest-side reads, and the script
# writes guest-probe back through the same mount. The host verifies that write.
set +e
runas testuser timeout --signal=TERM --kill-after=10s 90s \
    systemd-vmspawn \
    --user \
    --register=no \
    --no-ask-password \
    --machine="$MACHINE" \
    --ram=512M \
    --kvm=no \
    --vsock=no \
    --image="$IMAGE" \
    --image-format=raw \
    --linux="$KERNEL" \
    --bind="$SHARE" \
    --tpm=no \
    --efi-nvram-state=off \
    --console=headless \
    root=/dev/vda \
    rootfstype=ext4 \
    rootwait rw \
    "systemd.run=\"$SHARE/guest-probe.sh\"" \
    >"$LOG" 2>&1
rc=$?
set -e

cat "$LOG"

if grep -F 'Failed to enter user namespace for virtiofsd: Operation not permitted' "$LOG"; then
    echo "vmspawn reproduced the unmapped-bind namespace failure"
    exit 1
fi

if [[ $rc -ne 0 ]]; then
    echo "vmspawn guest-visible bind probe exited with status $rc"
    exit 1
fi

runas testuser grep -Fxq vmspawn-guest-ok "$SHARE/guest-probe"
echo "vmspawn ordinary-user bind is readable and writable inside the guest"
