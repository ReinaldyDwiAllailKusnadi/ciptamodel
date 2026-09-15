#!/bin/sh
# CiptaModel SQLite backup — online-safe via the SQLite backup API (WAL-aware).
# Usage: sh deploy/backup.sh [/opt/ciptamodel] [/var/backups/ciptamodel]
# Keeps the 14 newest snapshots. Never commit snapshots (see .gitignore: data/, *.db).
set -eu
APP_DIR="${1:-/opt/ciptamodel}"
BACKUP_DIR="${2:-/var/backups/ciptamodel}"
mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y-%m-%d-%H%M)"
SRC="$APP_DIR/data/ciptamodel.db"
DST="$BACKUP_DIR/ciptamodel-$STAMP.db"
node -e "require('better-sqlite3')(process.argv[1]).backup(process.argv[2]).then(()=>console.log('backup ok'))" "$SRC" "$DST"
chmod 600 "$DST"
ls -1t "$BACKUP_DIR"/ciptamodel-*.db | tail -n +15 | xargs -r rm -f
echo "kept: $(ls -1 "$BACKUP_DIR"/ciptamodel-*.db | wc -l) snapshots"
