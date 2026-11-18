const { createPublicKey, verify } = require('node:crypto');

const organizations = new Map([
    ['Org1MSP', 'security'],
    ['Org2MSP', 'information_center'],
]);
const digestPattern = /^[0-9a-f]{64}$/;
const identifierPattern = /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$/;
const releaseIdentifierPattern = /^[a-zA-Z0-9_-]{1,80}$/;
const kinds = new Set(['prompt', 'agent_config', 'tool_manifest', 'policy', 'knowledge']);

function requireValid(condition, code) {
    if (!condition) throw new Error(code);
}

function matches(value, pattern) {
    return typeof value === 'string' && pattern.exec(value)?.[0] === value;
}

function object(value, fields) {
    requireValid(value && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === fields.length
        && fields.every(field => Object.hasOwn(value, field)), 'INVALID_ARGUMENT');
}

function integer(value, min, max = Number.MAX_SAFE_INTEGER) {
    return Number.isSafeInteger(value) && min <= value && value <= max;
}

function canonical(value) {
    // All signed fields are ASCII scalars with fixed, non-numeric keys.
    return JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
}

function stateKey(stub, type, ...parts) {
    return stub.createCompositeKey(type, parts);
}

async function read(stub, key) {
    const bytes = await stub.getState(key);
    return bytes.length ? JSON.parse(Buffer.from(bytes).toString('utf8')) : null;
}

async function write(stub, key, record) {
    await stub.putState(key, Buffer.from(JSON.stringify(record)));
    return record;
}

function authorize(identity, role, msp) {
    const caller = identity.getMSPID();
    requireValid(organizations.has(caller) && (!msp || msp === caller)
        && identity.assertAttributeValue('role_b', role), 'FORBIDDEN');
    return organizations.get(caller);
}

async function registerApprover(stub, identity, spki) {
    const organization = authorize(identity, 'approver');
    const bytes = Buffer.from(spki, 'base64url');
    requireValid(bytes.toString('base64url') === spki && bytes.length === 44, 'INVALID_KEY');
    const key = createPublicKey({key: bytes, format: 'der', type: 'spki'});
    requireValid(key.asymmetricKeyType === 'ed25519'
        && key.export({format: 'der', type: 'spki'}).equals(bytes), 'INVALID_KEY');
    const keyId = stateKey(stub, 'approver', organization);
    const previous = await read(stub, keyId);
    if (previous) {
        requireValid(previous.spki === spki, 'KEY_ALREADY_REGISTERED');
        return previous;
    }
    // Read both key slots so concurrent enrollment cannot register the same key twice.
    const other = [...organizations.values()].find(org => org !== organization);
    const otherKey = await read(stub, stateKey(stub, 'approver', other));
    requireValid(otherKey?.spki !== spki, 'KEY_REUSED_ACROSS_ORGS');
    return write(stub, keyId, {organization, spki});
}

async function approve(stub, identity, input) {
    const organization = authorize(identity, 'approver');
    const signed = JSON.parse(input);
    object(signed, ['claims', 'signature']);
    const { claims, signature } = signed;
    object(claims, ['channel', 'operation_digest', 'organization', 'issued_at', 'expires_at']);
    requireValid(claims.channel === stub.getChannelID() && claims.organization === organization
        && matches(claims.operation_digest, digestPattern) && integer(claims.issued_at, 1)
        && integer(claims.expires_at, 1), 'INVALID_ARGUMENT');
    const now = Number(stub.getTxTimestamp().seconds.toString());
    requireValid(claims.issued_at <= now && now < claims.expires_at
        && claims.expires_at - claims.issued_at <= 3600, 'APPROVAL_TIME_INVALID');
    const registered = await read(stub, stateKey(stub, 'approver', organization));
    requireValid(registered && typeof signature === 'string' && signature.length === 86, 'BAD_SIGNATURE');
    const raw = Buffer.from(signature, 'base64url');
    const key = createPublicKey({key: Buffer.from(registered.spki, 'base64url'), format: 'der', type: 'spki'});
    const payload = Buffer.from('edge-agent-trust:b-approval:v1\n' + canonical(claims));
    requireValid(raw.toString('base64url') === signature && verify(null, payload, key, raw), 'BAD_SIGNATURE');

    const ref = claims.operation_digest;
    const keyId = stateKey(stub, 'approval', ref);
    const record = await read(stub, keyId) ?? { reference: ref, approvals: [], revocation: null };
    requireValid(!record.revocation, 'APPROVAL_REVOKED');
    const existing = record.approvals.find(item => item.claims.organization === organization);
    if (existing) {
        requireValid(existing.signature === signature, 'APPROVAL_ALREADY_RECORDED');
        return record;
    }
    record.approvals.push({claims: JSON.parse(canonical(claims)), signature});
    return write(stub, keyId, record);
}

async function revokeApproval(stub, identity, reference) {
    const organization = authorize(identity, 'approver');
    requireValid(matches(reference, digestPattern), 'INVALID_ARGUMENT');
    const key = stateKey(stub, 'approval', reference);
    const record = await read(stub, key);
    requireValid(record?.approvals.some(item => item.claims.organization === organization), 'APPROVAL_NOT_FOUND');
    if (record.revocation) return record;
    record.revocation = {organization, tx_id: stub.getTxID()};
    return write(stub, key, record);
}

function releaseKey(stub, scope, kind, artifactId) {
    requireValid(matches(scope, releaseIdentifierPattern) && kinds.has(kind)
        && matches(artifactId, releaseIdentifierPattern), 'INVALID_ARGUMENT');
    return stateKey(stub, 'release', scope, kind, artifactId);
}

async function publishRelease(stub, identity, input) {
    authorize(identity, 'publisher', 'Org2MSP');
    const ref = JSON.parse(input);
    object(ref, ['scope', 'kind', 'artifact_id', 'version', 'manifest_sha256']);
    const key = releaseKey(stub, ref.scope, ref.kind, ref.artifact_id);
    requireValid(integer(ref.version, 1, 2147483647) && matches(ref.manifest_sha256, digestPattern),
        'INVALID_ARGUMENT');
    const previous = await read(stub, key);
    if (previous) {
        requireValid(ref.version >= previous.version, 'RELEASE_ROLLBACK');
        if (ref.version === previous.version) {
            requireValid(!previous.revoked && ref.manifest_sha256 === previous.manifest_sha256, 'RELEASE_CONFLICT');
            return previous;
        }
    }
    return write(stub, key, {...ref, revoked: false});
}

async function revokeRelease(stub, identity, input) {
    authorize(identity, 'publisher', 'Org2MSP');
    const ref = JSON.parse(input);
    object(ref, ['scope', 'kind', 'artifact_id', 'version', 'manifest_sha256']);
    const key = releaseKey(stub, ref.scope, ref.kind, ref.artifact_id);
    const previous = await read(stub, key);
    requireValid(previous && previous.version === ref.version
        && previous.manifest_sha256 === ref.manifest_sha256, 'RELEASE_CONFLICT');
    return previous.revoked ? previous : write(stub, key, {...previous, revoked: true});
}

async function anchorAudit(stub, identity, input) {
    authorize(identity, 'auditor', 'Org1MSP');
    const batch = JSON.parse(input);
    object(batch, ['stream', 'first_seq', 'last_seq', 'root']);
    requireValid(matches(batch.stream, identifierPattern) && integer(batch.first_seq, 1)
        && integer(batch.last_seq, batch.first_seq, Number.MAX_SAFE_INTEGER - 1)
        && matches(batch.root, digestPattern), 'INVALID_ARGUMENT');
    const key = stateKey(stub, 'audit', batch.stream, String(batch.first_seq));
    const previous = await read(stub, key);
    if (previous) {
        requireValid(canonical(previous) === canonical(batch), 'AUDIT_CONFLICT');
        return previous;
    }
    const headKey = stateKey(stub, 'audit-head', batch.stream);
    const head = await read(stub, headKey);
    requireValid(batch.first_seq === (head?.last_seq ?? 0) + 1, 'AUDIT_RANGE_INVALID');
    await write(stub, headKey, {last_seq: batch.last_seq});
    return write(stub, key, batch);
}

const methods = new Map([
    ['RegisterApprover', [1, registerApprover]],
    ['Approve', [1, approve]],
    ['RevokeApproval', [1, revokeApproval]],
    ['ReadApproval', [1, (stub, _, ref) => {
        requireValid(matches(ref, digestPattern), 'INVALID_ARGUMENT');
        return read(stub, stateKey(stub, 'approval', ref));
    }]],
    ['PublishRelease', [1, publishRelease]],
    ['RevokeRelease', [1, revokeRelease]],
    ['ReadRelease', [3, (stub, _, ...args) => read(stub, releaseKey(stub, ...args))]],
    ['AnchorAudit', [1, anchorAudit]],
    ['ReadAuditHead', [1, (stub, _, stream) => {
        requireValid(matches(stream, identifierPattern), 'INVALID_ARGUMENT');
        return read(stub, stateKey(stub, 'audit-head', stream));
    }]],
    ['ReadAudit', [2, (stub, _, stream, first) => {
        requireValid(matches(stream, identifierPattern) && /^[1-9][0-9]*$/.test(first)
            && integer(Number(first), 1) && String(Number(first)) === first, 'INVALID_ARGUMENT');
        return read(stub, stateKey(stub, 'audit', stream, first));
    }]],
]);

async function invoke(stub, identity, name, args) {
    const method = methods.get(name);
    requireValid(method && method[0] === args.length && args.every(arg => arg.length <= 4096), 'INVALID_ARGUMENT');
    return method[1](stub, identity, ...args);
}

module.exports = { invoke };
