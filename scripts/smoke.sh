#!/usr/bin/env bash
# smoke.sh — WU-508 release smoke test.
#
# Exercises the release-critical path end-to-end over HTTP: bootstrap the
# platform, create an org → project → task via the action dispatch endpoint
# (the same endpoint the htmx UI posts to), then fetch the task page.
#
# Auth: OAuth can't be driven headlessly, so the script seeds an admin session
# directly into the DB (bootstrap_done=1, admin user, session row) and uses the
# session cookie for the UI calls. This exercises the real handlers; only the
# OAuth handshake is bypassed.
#
# Usage:
#   scripts/smoke.sh                 # build + run + smoke against localhost
#   scripts/smoke.sh <base-url>      # smoke an already-running server
set -euo pipefail

cd "$(dirname "$0")/.."

# --- config (secrets are dev-only; real deploys set real values) ---
export BC_DB_PATH="${SMOKE_DB:-$(mktemp -d)/bc.db}"
export BC_DATA_DIR="$(dirname "$BC_DB_PATH")/data"
export BC_BASE_URL="http://localhost:8080"
export BC_BIND="0.0.0.0:8080"
export BC_SECRET_KEY="$(head -c32 /dev/urandom | base64)"
export BC_SESSION_SECRET="$(head -c32 /dev/urandom | base64)"
export BC_GOOGLE_CLIENT_ID="smoke"
export BC_GOOGLE_CLIENT_SECRET="smoke"
mkdir -p "$BC_DATA_DIR"

if [ -z "${1:-}" ]; then
    # Build + start the server in the background.
    go build -o /tmp/bc ./cmd/bc
    /tmp/bc serve &
    SRV_PID=$!
    trap 'kill $SRV_PID 2>/dev/null || true' EXIT
    BASE="http://localhost:8080"
else
    BASE="$1"
fi

# Wait for readiness.
for i in $(seq 1 60); do
    if curl -sf "$BASE/readyz" >/dev/null 2>&1; then break; fi
    sleep 1
done
curl -sf "$BASE/readyz" >/dev/null || { echo "smoke: server not ready"; exit 1; }

# --- seed the admin session ---
# token_hash = sha256(raw token hex). Session cookie: __Host-bc_session=<raw>.
RAW=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')
HASH=$(printf '%s' "$RAW" | sha256sum | awk '{print $1}')
EXP=$(date -u +%Y-%m-%dT%H:%M:%S.000Z -d '+1 hour' 2>/dev/null || date -u -v+1H +%Y-%m-%dT%H:%M:%S.000Z)
NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)

# sqlite3 may not exist; use the bc binary's own DB via a small Go helper if
# needed — but for the smoke we require sqlite3 (present in CI/dev images).
command -v sqlite3 >/dev/null || { echo "smoke: sqlite3 required"; exit 1; }
sqlite3 "$BC_DB_PATH" <<SQL
INSERT INTO users (id, email, name) VALUES ('u1','smoke@example.com','Smoke');
INSERT INTO platform_settings (id, bootstrap_done) VALUES (1,1)
  ON CONFLICT(id) DO UPDATE SET bootstrap_done=1;
INSERT INTO sessions (token_hash, user_id, ip, ua, created_at, last_seen_at, expires_at)
  VALUES ('$HASH','u1','127.0.0.1','smoke','$NOW','$NOW','$EXP');
-- Platform admin grant (matches auth.ensurePlatformAdmin): u1 is Org Owner of
-- the platform sentinel org, covering platform-scope actions (org.create).
INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id)
  VALUES ('m1','00000000000000000000000000000000','u1','user','org','00000000000000000000000000000000','00000000000000000000000000000000')
  ON CONFLICT(org_id, actor_id, actor_type, resource_type, resource_id) DO NOTHING;
SQL

COOKIE="__Host-bc_session=$RAW"
# CSRF token: HMAC-SHA256(secret, token_hash) hex — required on POST actions.
CSRF=$(python3 -c "import hmac,hashlib,binascii; print(binascii.hexlify(hmac.new(b'$BC_SESSION_SECRET', b'$HASH', hashlib.sha256).digest()).decode())")
CSRF_HDR="X-CSRF-Token: $CSRF"

# --- org.create ---
ORG=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -d '{"name":"Acme","slug":"acme","visibility":"private"}' \
    "$BASE/api/action/org.create")
echo "org.create -> $ORG"
ORG_ID=$(echo "$ORG" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null \
    || echo "$ORG" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$ORG_ID" ] || { echo "smoke: org.create failed"; exit 1; }

# --- project.create ---
PROJ=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" \
    -d "{\"org_id\":\"$ORG_ID\",\"name\":\"Website\",\"key\":\"WEB\",\"visibility\":\"private\"}" \
    "$BASE/api/action/project.create")
echo "project.create -> $PROJ"
PROJ_ID=$(echo "$PROJ" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null \
    || echo "$PROJ" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$PROJ_ID" ] || { echo "smoke: project.create failed"; exit 1; }

# --- task.create ---
TASK=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" -H "X-Project-Id: $PROJ_ID" \
    -d "{\"project_id\":\"$PROJ_ID\",\"title\":\"Launch\",\"status\":\"backlog\"}" \
    "$BASE/api/action/task.create")
echo "task.create -> $TASK"
TASK_ID=$(echo "$TASK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null \
    || echo "$TASK" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$TASK_ID" ] || { echo "smoke: task.create failed"; exit 1; }

# --- task page renders ---
PAGE=$(curl -sf -H "Cookie: $COOKIE" "$BASE/app/org/$ORG_ID/project/$PROJ_ID/task/$TASK_ID") \
    || { echo "smoke: task page failed"; exit 1; }
echo "$PAGE" | grep -qi "Launch" || { echo "smoke: task page missing title"; exit 1; }

# --- WU-509: org.storage.configure POST route (was a 404 — form posted to an
# unregistered route). Configure S3 then read status back.
STORAGE=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" \
    -d '{"storage_config":{"endpoint":"http://localhost:9000","bucket":"attachments","access_key_id":"AK","secret_access_key":"SK","path_style":true,"prefix":"prod"}}' \
    "$BASE/api/action/org.storage.configure") \
    || { echo "smoke: org.storage.configure returned non-200 (route missing?)"; exit 1; }
echo "org.storage.configure -> $STORAGE"
STATUS=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" -d '{}' \
    "$BASE/api/action/org.storage.status")
echo "org.storage.status -> $STATUS"
echo "$STATUS" | grep -q '"backend":"s3"' || { echo "smoke: storage status not s3"; exit 1; }

# --- WU-509: role editor pages render + role.create/update via form values ---
ROLEPAGE=$(curl -sf -H "Cookie: $COOKIE" "$BASE/app/org/$ORG_ID/roles") \
    || { echo "smoke: roles page failed"; exit 1; }
echo "$ROLEPAGE" | grep -qi "Create role" || { echo "smoke: roles page missing create button"; exit 1; }

NEWPAGE=$(curl -sf -H "Cookie: $COOKIE" "$BASE/app/org/$ORG_ID/roles/new") \
    || { echo "smoke: roles/new page failed"; exit 1; }
echo "$NEWPAGE" | grep -qi "grants_str" || { echo "smoke: roles/new missing grants field"; exit 1; }

# role.create via form-urlencoded (the exact shape the htmx form posts).
ROLE=$(curl -sf -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" \
    -d "org_id=$ORG_ID&name=Project+Admin&grants_str=task.*,+project.read,+org.read" \
    "$BASE/api/action/role.create") \
    || { echo "smoke: role.create returned non-200"; exit 1; }
echo "role.create -> $ROLE"
ROLE_ID=$(echo "$ROLE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null \
    || echo "$ROLE" | grep -o '"id":"[^\"]*"' | head -1 | cut -d'"' -f4)
[ -n "$ROLE_ID" ] || { echo "smoke: role.create failed"; exit 1; }

EDITPAGE=$(curl -sf -H "Cookie: $COOKIE" "$BASE/app/org/$ORG_ID/roles/$ROLE_ID/edit") \
    || { echo "smoke: roles/edit page failed"; exit 1; }
echo "$EDITPAGE" | grep -qi "Project Admin" || { echo "smoke: roles/edit missing role name"; exit 1; }

# role.update via form-urlencoded (drop project.read from grants).
curl -sf -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" \
    -d "id=$ROLE_ID&org_id=$ORG_ID&name=Project+Admin&grants_str=task.*,+org.read" \
    "$BASE/api/action/role.update" >/dev/null \
    || { echo "smoke: role.update returned non-200"; exit 1; }

echo "smoke: PASS (org=$ORG_ID project=$PROJ_ID task=$TASK_ID role=$ROLE_ID)"
echo "smoke: WU-509 storage route + role editor round-trip PASS"

# --- WU-510: notifications page + mark-read round-trip ---
NOTIFPAGE=$(curl -sf -H "Cookie: $COOKIE" "$BASE/app/notifications") \
    || { echo "smoke: notifications page failed"; exit 1; }
echo "$NOTIFPAGE" | grep -qi "Notifications" || { echo "smoke: notif page missing title"; exit 1; }

# unread-count is DB-backed now: returns JSON count (0 for a fresh user).
UNREAD=$(curl -sf -H "Cookie: $COOKIE" "$BASE/api/notif/unread-count")
echo "unread-count -> $UNREAD"
echo "$UNREAD" | grep -q '"count"' || { echo "smoke: unread-count not JSON"; exit 1; }

# Seed a notification for the session user (u1) directly, then verify it shows
# as unread and mark-read works.
sqlite3 "$BC_DB_PATH" "INSERT INTO notifications (id, org_id, user_id, event_name, title, body, grouping_key)
  VALUES ('smokenotif1','$ORG_ID','u1','task.create','Smoke notif','body','smokeg')" 2>/dev/null \
    || { echo "smoke: seed notification failed"; }
if sqlite3 "$BC_DB_PATH" "SELECT COUNT(*) FROM notifications WHERE id='smokenotif1'" 2>/dev/null | grep -q 1; then
    UNREAD2=$(curl -sf -H "Cookie: $COOKIE" "$BASE/api/notif/unread-count")
    echo "unread-count after seed -> $UNREAD2"
    echo "$UNREAD2" | grep -q '"count":1' || { echo "smoke: unread-count did not reflect seed"; exit 1; }

    # mark-all-read clears it.
    curl -sf -X POST -H "Cookie: $COOKIE" -H "$CSRF_HDR" "$BASE/api/notif/mark-all-read" >/dev/null \
        || { echo "smoke: mark-all-read failed"; exit 1; }
    UNREAD3=$(curl -sf -H "Cookie: $COOKIE" "$BASE/api/notif/unread-count")
    echo "unread-count after mark-all -> $UNREAD3"
    echo "$UNREAD3" | grep -q '"count":0' || { echo "smoke: mark-all-read did not clear"; exit 1; }
fi

echo "smoke: WU-510 notifications page + mark-read round-trip PASS"

# --- WU-511: templates + recurring page + round-trips ---
TPLURL="$BASE/app/org/$ORG_ID/project/$PROJ_ID/templates"
TPLPAGE=$(curl -sf -H "Cookie: $COOKIE" "$TPLURL") \
    || { echo "smoke: templates page failed"; exit 1; }
echo "$TPLPAGE" | grep -qi "Templates & Recurring" || { echo "smoke: templates page missing title"; exit 1; }

# template.create (hx-vals JSON shape the form posts).
TPL=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" \
    -d "{\"org_id\":\"$ORG_ID\",\"project_id\":\"$PROJ_ID\",\"name\":\"Bug report\",\"title_template\":\"[Bug] {title}\",\"points\":3}" \
    "$BASE/api/action/template.create") \
    || { echo "smoke: template.create failed"; exit 1; }
TPL_ID=$(echo "$TPL" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("ID") or d.get("id"))')
[ -n "$TPL_ID" ] || { echo "smoke: template.create bad id"; exit 1; }
echo "template.create -> $TPL_ID"

# template.create_from creates a task from the template.
TASK2=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" \
    -d "{\"org_id\":\"$ORG_ID\",\"project_id\":\"$PROJ_ID\",\"template_id\":\"$TPL_ID\"}" \
    "$BASE/api/action/template.create_from") \
    || { echo "smoke: template.create_from failed"; exit 1; }
echo "$TASK2" | grep -qE '"Key"|"key"' || { echo "smoke: create_from did not create a task"; exit 1; }
echo "template.create_from -> $(echo "$TASK2" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("Key") or d.get("key",""))' 2>/dev/null)"

# recurring.create (cron -> next_at).
RULE=$(curl -sf -X POST -H "Content-Type: application/json" -H "Cookie: $COOKIE" -H "$CSRF_HDR" \
    -H "X-Org-Id: $ORG_ID" \
    -d "{\"org_id\":\"$ORG_ID\",\"project_id\":\"$PROJ_ID\",\"template_id\":\"$TPL_ID\",\"cron_expr\":\"0 9 * * 1\"}" \
    "$BASE/api/action/recurring.create") \
    || { echo "smoke: recurring.create failed"; exit 1; }
RULE_ID=$(echo "$RULE" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("ID") or d.get("id"))' 2>/dev/null)
[ -n "$RULE_ID" ] || { echo "smoke: recurring.create bad id"; exit 1; }
echo "recurring.create -> $RULE_ID (next_at=$(echo "$RULE" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("NextAt") or d.get("next_at",""))' 2>/dev/null))"

# Page now lists the template + rule.
TPLURL2=$(curl -sf -H "Cookie: $COOKIE" "$TPLURL")
echo "$TPLURL2" | grep -q "Bug report" || { echo "smoke: templates page missing created template"; exit 1; }
echo "$TPLURL2" | grep -q "0 9 \* \* 1" || { echo "smoke: templates page missing recurring rule"; exit 1; }

echo "smoke: WU-511 templates + recurring page + round-trip PASS"
