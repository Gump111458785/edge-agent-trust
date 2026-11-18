#!/usr/bin/env bash
set -euo pipefail
umask 077

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
network="$(cd "${1:?Pass the path to fabric-samples/test-network}" && pwd)"
export PATH="$network/../bin:$PATH"

mkdir -p "$repo/role-b-results"
work="$(mktemp -d "$repo/role-b-results/fabric.XXXXXX")"

enroll() {
  local org="$1" port="$2" name="$3" role="$4"
  local domain="org${org}.example.com"
  local ca_name="ca-org${org}"
  local ca_cert="$network/organizations/fabric-ca/org${org}/ca-cert.pem"
  local enroller="$network/organizations/peerOrganizations/$domain"
  local secret
  secret="$(python3 -c 'import secrets; print(secrets.token_hex(20))')"
  FABRIC_CA_CLIENT_HOME="$enroller" fabric-ca-client register -u "https://localhost:$port" \
    --caname "$ca_name" --tls.certfiles "$ca_cert" --id.name "role-b-$name" \
    --id.type client --id.secret "$secret" --id.attrs "role_b=$role:ecert" >/dev/null
  FABRIC_CA_CLIENT_HOME="$enroller" fabric-ca-client enroll -u "https://role-b-$name:$secret@localhost:$port" \
    --caname "$ca_name" --tls.certfiles "$ca_cert" -M "$work/$name.msp" >&2
}

cd "$network"
./network.sh up createChannel -ca -c roleb \
  -i "${ROLE_B_FABRIC_VERSION:-2.5.16}" -cai "${ROLE_B_CA_VERSION:-1.5.22}" >&2
./network.sh deployCC -c roleb -ccn roleb -ccp "$repo/role_b/chaincode" \
  -ccl javascript -ccep "AND('Org1MSP.peer','Org2MSP.peer')" >&2
enroll 1 7054 security approver
enroll 2 8054 information_center approver
enroll 1 7054 auditor auditor
enroll 2 8054 publisher publisher

cd "$repo"
(cd role_b/client && npm ci >&2)
python3 -m role_b.tests.experiment "$work" --prepare "$network"
printf '%s\n' "$work"
