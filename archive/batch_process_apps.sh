#!/bin/bash
# Batch processor for 0330 app classification task
# This script triggers Claude Code to process the next batch of pending apps
# Runs every 10 minutes via cron

cd /root/coding/app_control

# Check if a processing lock exists (prevent overlapping runs)
LOCKFILE="archive/.processing.lock"
if [ -f "$LOCKFILE" ]; then
    # Check if lock is older than 30 minutes (stale lock)
    if [ "$(find "$LOCKFILE" -mmin +30 2>/dev/null)" ]; then
        rm -f "$LOCKFILE"
        echo "Removed stale lock file"
    else
        echo "Another batch is still processing, exiting"
        exit 0
    fi
fi

# Create lock
touch "$LOCKFILE"

# Count remaining pending tasks
PENDING=$(python3 -c "
import csv
count = 0
with open('archive/0330tasks.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['状态'] == 'pending':
            count += 1
print(count)
")

DONE=$(python3 -c "
import csv
count = 0
with open('archive/0330tasks.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['状态'] == 'done':
            count += 1
print(count)
")

echo "=== 0330 App Classification Batch Processor ==="
echo "Pending: $PENDING | Done: $DONE | Total: $((PENDING + DONE))"

if [ "$PENDING" -eq 0 ]; then
    echo "All apps have been processed!"
    rm -f "$LOCKFILE"
    exit 0
fi

echo "Triggering batch processing..."
