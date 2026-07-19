#!/usr/bin/env bash
# check-scope.sh — CI gate for SPEC §1 rule 2: every sqlc query that touches
# a tenant table must bind an org_id parameter.
#
# Usage:
#   scripts/check-scope.sh              self-test, then scan internal/db/queries
#   scripts/check-scope.sh --self-test  self-test only
#
# TENANT_TABLES is the authoritative list, maintained here. Grow it in the
# same commit as any migration adding a tenant table (a table carrying
# org_id per SPEC §5 that is scoped by org). The migration-0001 tables
# (users, identities, sessions, platform_settings) are platform-scoped and
# deliberately absent, so the list starts empty.
#
# Deliberately excluded (SPEC §5), do NOT add these:
#   audit_log        — org_id is NULLABLE (platform/pre-org actions have no
#                      org); rows are written by the dispatch audit hook, not
#                      via org-scoped reads, so an org_id-required grep would
#                      be wrong here.
#   idempotency_keys — has no org_id at all; keyed globally by the
#                      idempotency key.
set -euo pipefail

cd "$(dirname "$0")/.."

TENANT_TABLES=""  # comma-separated, e.g. "orgs,teams,projects,tasks"
QUERIES_DIR="internal/db/queries"
FIXTURE_DIR="scripts/testdata/check-scope"

# scan_file FILE TABLES
# Splits FILE into sqlc query blocks (delimited by "-- name:" headers) and
# fails if any block references a tenant table without mentioning org_id.
scan_file() {
    local file="$1" tables="$2"
    awk -v tbls="$tables" -v file="$file" '
        BEGIN { n = split(tolower(tbls), T, ",") }
        function flush(   i, low) {
            if (block == "") return
            low = tolower(block)
            for (i = 1; i <= n; i++) {
                if (T[i] == "") continue
                if (low ~ ("(^|[^a-z0-9_])" T[i] "([^a-z0-9_]|$)") && low !~ /org_id/) {
                    printf "check-scope: %s: query \"%s\" touches tenant table \"%s\" without an org_id parameter\n", file, qname, T[i]
                    bad = 1
                }
            }
            block = ""
        }
        /^-- name:/ { flush(); qname = $3 }
        { block = block "\n" $0 }
        END { flush(); exit bad }
    ' "$file"
}

# scan_dir DIR TABLES — scan every .sql file; report all violations.
scan_dir() {
    local dir="$1" tables="$2" rc=0 f
    if [ ! -d "$dir" ]; then
        echo "check-scope: no queries directory at $dir — nothing to scan"
        return 0
    fi
    shopt -s nullglob
    for f in "$dir"/*.sql; do
        scan_file "$f" "$tables" || rc=1
    done
    shopt -u nullglob
    return $rc
}

# self_test — the gate must demonstrably fail on the committed violating
# fixture and pass on the compliant one, or the gate itself is broken.
self_test() {
    local rc=0
    if scan_file "$FIXTURE_DIR/fail_fixture.sql" "tasks" > /dev/null; then
        echo "check-scope: SELF-TEST FAILED: fail_fixture.sql was not flagged" >&2
        rc=1
    fi
    if ! scan_file "$FIXTURE_DIR/pass_fixture.sql" "tasks"; then
        echo "check-scope: SELF-TEST FAILED: pass_fixture.sql was wrongly flagged" >&2
        rc=1
    fi
    if [ "$rc" -ne 0 ]; then
        return 1
    fi
    echo "check-scope: self-test OK"
}

self_test

if [ "${1:-}" = "--self-test" ]; then
    exit 0
fi

if scan_dir "$QUERIES_DIR" "$TENANT_TABLES"; then
    echo "check-scope: OK"
else
    echo "check-scope: FAIL — tenant-table queries missing org_id (see above)" >&2
    exit 1
fi
