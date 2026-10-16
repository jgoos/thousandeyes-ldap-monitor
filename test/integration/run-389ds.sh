#!/usr/bin/env bash
# Starts a throwaway 389 Directory Server container, seeds a monitor account, runs the
# integration tests against it, and removes the container. Needs podman or docker.
set -euo pipefail

IMAGE="quay.io/389ds/dirsrv:c9s@sha256:40b6cd8370de9ed2856262c5f8a675aeb84c17cf9f7f6957fe7cc8d88988004a"
RUNTIME="${CONTAINER_RUNTIME:-$(command -v podman || command -v docker || true)}"
if [[ -z "$RUNTIME" ]]; then
  echo "podman or docker is required (or set CONTAINER_RUNTIME)" >&2
  exit 1
fi

NAME="ldap-monitor-it-$$"
CERT_HOSTNAME="ldap389.test"
SUFFIX="dc=example,dc=com"
DM_PASSWORD="dm-$RANDOM-$RANDOM-Aa1"
BIND_DN="cn=monitor,ou=people,$SUFFIX"
BIND_PASSWORD="mon-$RANDOM-$RANDOM-Aa1"
WORK_DIR="$(mktemp -d)"

cleanup() {
  "$RUNTIME" rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

"$RUNTIME" run -d --name "$NAME" --hostname "$CERT_HOSTNAME" \
  -e DS_DM_PASSWORD="$DM_PASSWORD" \
  -p 127.0.0.1::3389 -p 127.0.0.1::3636 \
  "$IMAGE" >/dev/null

echo "Waiting for 389 DS to start..."
for _ in $(seq 1 90); do
  if "$RUNTIME" logs "$NAME" 2>&1 | grep -q "389-ds-container started"; then break; fi
  sleep 2
done
"$RUNTIME" logs "$NAME" 2>&1 | grep -q "389-ds-container started" || {
  "$RUNTIME" logs "$NAME" >&2
  echo "389 DS did not start" >&2
  exit 1
}

"$RUNTIME" exec "$NAME" dsconf localhost backend create \
  --suffix "$SUFFIX" --be-name userroot --create-suffix --create-entries >/dev/null

# The ACI lets the monitor account read its own entry, as most directories allow by default.
"$RUNTIME" exec -i "$NAME" ldapadd -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w "$DM_PASSWORD" >/dev/null <<EOF
dn: $BIND_DN
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: monitor
sn: monitor
userPassword: $BIND_PASSWORD

dn: $SUFFIX
changetype: modify
add: aci
aci: (targetattr="*")(version 3.0; acl "self read"; allow (read,search,compare) userdn="ldap:///self";)
EOF

"$RUNTIME" exec "$NAME" cat /etc/dirsrv/slapd-localhost/Self-Signed-CA.pem > "$WORK_DIR/ca.pem"

host_port() { "$RUNTIME" port "$NAME" "$1/tcp" | head -n1 | sed 's/.*://'; }

LDAP_IT_HOSTNAME="$CERT_HOSTNAME" \
LDAP_IT_LDAP_PORT="$(host_port 3389)" \
LDAP_IT_LDAPS_PORT="$(host_port 3636)" \
LDAP_IT_CA_FILE="$WORK_DIR/ca.pem" \
LDAP_IT_BIND_DN="$BIND_DN" \
LDAP_IT_BIND_PASSWORD="$BIND_PASSWORD" \
  node --test test/integration/*.test.js
