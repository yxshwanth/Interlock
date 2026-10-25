#!/usr/bin/env bash
# Every tracked, non-generated .go file carries an Apache-2.0 SPDX header.
# internal/ebpf/bpf/connect.c is GPL-2.0 on purpose: the kernel only lets
# GPL-compatible programs call the BPF helpers it uses. It must still carry an
# SPDX line.
set -euo pipefail
cd "$(dirname "$0")/.."
rc=0
while read -r f; do
	head -1 "$f" | grep -q '^// Code generated' && continue
	head -1 "$f" | grep -qx '// SPDX-License-Identifier: Apache-2.0' || { echo "missing SPDX Apache-2.0 header: $f"; rc=1; }
done < <(git ls-files '*.go')
head -1 internal/ebpf/bpf/connect.c | grep -qx '// SPDX-License-Identifier: GPL-2.0' || { echo "connect.c: expected GPL-2.0 SPDX line"; rc=1; }
exit $rc
