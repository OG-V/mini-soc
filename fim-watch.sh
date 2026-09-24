#!/bin/bash
# Polls a fixed watchlist of security-critical files every 5s and logs any
# hash change (the file's content was modified) to stdout, so it can be
# redirected into a log file the collector tails like any other source.
# A basic, from-scratch example of file integrity monitoring (FIM) - it
# reports WHAT changed, not WHO changed it (that would need process-level
# auditing, e.g. auditd or eBPF, which is out of scope here).

WATCHLIST=(/etc/passwd /etc/shadow /etc/sudoers /root/.ssh/authorized_keys)
declare -A last_hash

while true; do
    for f in "${WATCHLIST[@]}"; do
        if [ -f "$f" ]; then
            current_hash=$(sha256sum "$f" | awk '{print $1}')
        else
            current_hash="MISSING"
        fi

        if [ -n "${last_hash[$f]}" ] && [ "${last_hash[$f]}" != "$current_hash" ]; then
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") FILE_CHANGED $f ${last_hash[$f]} ${current_hash}"
        fi

        last_hash[$f]="$current_hash"
    done
    sleep 5
done
