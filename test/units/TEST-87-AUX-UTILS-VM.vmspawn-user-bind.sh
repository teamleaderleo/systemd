#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Reproduce systemd-vmspawn --user --bind failing before virtiofsd exec when no
# user namespace mapping is requested for the bind.
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

if ! id testuser >/dev/null 2>&1; then
    echo "testuser not found, skipping"
    exit 0
fi

KERNEL=""
for k in /usr/lib/modules/"$(uname -r)"/vmlinuz /boot/vmlinuz-"$(uname -r)" /boot/vmlinuz; do
    if [[ -f "$k" ]]; then
        KERNEL="$k"
        break
    fi
done

if [[ -z "$KERNEL" ]]; then
    echo "No kernel found for direct VM boot, skipping"
    exit 0
fi

TEST_UID="$(id -u testuser)"
LINGER_WAS_ENABLED=0
USER_MANAGER_WAS_ACTIVE=0
if [[ "$(loginctl show-user testuser -p Linger --value 2>/dev/null || true)" == yes ]]; then
    LINGER_WAS_ENABLED=1
fi
if systemctl is-active --quiet "user@${TEST_UID}.service"; then
    USER_MANAGER_WAS_ACTIVE=1
fi

MACHINE="test-vmspawn-user-bind-$$"
WORKDIR="$(mktemp -d /tmp/test-vmspawn-user-bind.XXXXXXXXXX)"
LOG="$WORKDIR/vmspawn.log"

# Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2317
at_exit() {
    set +e

    # The timeout should stop vmspawn, whose child processes use parent-death
    # signals. Retain a unique-process fallback so a failed test cannot leave a
    # QEMU or virtiofsd instance behind.
    pkill -TERM -f "${MACHINE}" 2>/dev/null
    sleep 0.2
    pkill -KILL -f "${MACHINE}" 2>/dev/null

    rm -rf "$WORKDIR"

    if (( USER_MANAGER_WAS_ACTIVE == 0 )); then
        systemctl stop "user@${TEST_UID}.service" 2>/dev/null
    fi
    if (( LINGER_WAS_ENABLED == 0 )); then
        loginctl disable-linger testuser 2>/dev/null
    fi
}
trap at_exit EXIT

if (( LINGER_WAS_ENABLED == 0 )); then
    loginctl enable-linger testuser
fi
if (( USER_MANAGER_WAS_ACTIVE == 0 )); then
    systemctl start "user@${TEST_UID}.service"
fi

chown testuser:testuser "$WORKDIR"
runas testuser mkdir "$WORKDIR/share"
runas testuser sh -c "printf '%s\n' vmspawn-user-bind-ok >'$WORKDIR/share/host-probe'"
runas testuser truncate -s 64M "$WORKDIR/root.raw"

# The raw disk deliberately has no filesystem. The guest does not need to boot
# for this first discriminator: baseline vmspawn exits before virtiofsd exec,
# while a correct host-side path reaches QEMU and remains alive until timeout.
set +e
runas testuser timeout --signal=TERM --kill-after=5s 8s \
    systemd-vmspawn \
    --user \
    --register=no \
    --keep-unit \
    --no-ask-password \
    --notify-ready=no \
    --machine="$MACHINE" \
    --ram=256M \
    --kvm=no \
    --vsock=no \
    --image="$WORKDIR/root.raw" \
    --image-format=raw \
    --linux="$KERNEL" \
    --bind="$WORKDIR/share" \
    --tpm=no \
    --console=headless \
    root=/dev/vda rw \
    >"$LOG" 2>&1
rc=$?
set -e

cat "$LOG"

if [[ $rc -eq 124 ]]; then
    echo "vmspawn reached its long-running QEMU phase with an ordinary-user bind"
    exit 0
fi

if grep -Eq 'vhost-user-fs-pci|virtiofs.*QMP|is not a valid device model name' "$LOG"; then
    echo "QEMU lacks usable vhost-user-fs support, skipping"
    exit 0
fi

if grep -F 'Failed to enter user namespace for virtiofsd: Operation not permitted' "$LOG"; then
    echo "vmspawn reproduced the unmapped-bind namespace failure"
else
    echo "vmspawn exited before the expected timeout with status $rc"
fi

exit 1
