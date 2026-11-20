const assert = require('node:assert/strict');
const { generateKeyPairSync, sign } = require('node:crypto');
const { test } = require('node:test');
const { invoke } = require('../chaincode/ledger');

const digest = 'a'.repeat(64);
const now = 1700000000;

function fixture() {
    const state = new Map();
    const stub = {
        getState: async key => state.get(key) ?? Buffer.alloc(0),
        putState: async (key, value) => state.set(key, value),
        createCompositeKey: (name, parts) => JSON.stringify([name, ...parts]),
        getChannelID: () => 'roleb',
        getTxTimestamp: () => ({seconds: BigInt(now)}),
        getTxID: () => '1'.repeat(64),
    };
    const call = (msp, role, fn, ...args) =>
        invoke(stub, {getMSPID: () => msp, assertAttributeValue: (_, value) => role === value},
            fn, args.map(arg => typeof arg === 'string' ? arg : JSON.stringify(arg)));
    const org1 = (fn, ...args) => call('Org1MSP', 'approver', fn, ...args);
    const org2 = (fn, ...args) => call('Org2MSP', 'approver', fn, ...args);
    return { call, org1, org2 };
}

function approver(organization) {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const spki = publicKey.export({type: 'spki', format: 'der'}).toString('base64url');
    const make = (overrides = {}) => {
        const claims = {channel: 'roleb', expires_at: now + 60, issued_at: now,
            operation_digest: digest, organization, ...overrides};
        const signature = sign(null, Buffer.from('edge-agent-trust:b-approval:v1\n' + JSON.stringify(claims)),
            privateKey).toString('base64url');
        return {claims, signature};
    };
    return {spki, make};
}

test('separate identities, immutable independent keys, binding, expiry and revocation', async () => {
    const { call, org1, org2 } = fixture();
    const first = approver('security');
    const second = approver('information_center');
    await assert.rejects(call('Org1MSP', 'reader', 'RegisterApprover', first.spki), /FORBIDDEN/);
    await org1('RegisterApprover', first.spki);
    await assert.rejects(org2('RegisterApprover', first.spki), /KEY_REUSED_ACROSS_ORGS/);
    await org2('RegisterApprover', second.spki);
    await assert.rejects(org1('RegisterApprover', second.spki), /KEY_ALREADY_REGISTERED/);
    await assert.rejects(org1('Approve', second.make()), /INVALID_ARGUMENT/);
    await assert.rejects(org1('Approve', first.make({expires_at: now})), /APPROVAL_TIME_INVALID/);
    const approved = first.make();
    const altered = { ...approved, claims: {...approved.claims, operation_digest: 'b'.repeat(64)} };
    await assert.rejects(org1('Approve', altered), /BAD_SIGNATURE/);
    const pending = await org1('Approve', approved);
    assert.equal(pending.approvals.length, 1);
    assert.deepEqual(await org1('Approve', approved), pending);
    const complete = await org2('Approve', second.make());
    assert.equal(complete.approvals.length, 2);
    const revoked = await org2('RevokeApproval', digest);
    assert.equal(revoked.revocation.organization, 'information_center');
    assert.deepEqual(await org2('ReadApproval', digest), revoked);
    await assert.rejects(org1('Approve', approved), /APPROVAL_REVOKED/);
});

test('release anchors reject unauthorized writes, conflicting versions and rollbacks', async () => {
    const { call, org1 } = fixture();
    const publish = (fn, ref) => call('Org2MSP', 'publisher', fn, ref);
    const ref = {scope: 'campus', kind: 'knowledge', artifact_id: 'rules', version: 1, manifest_sha256: digest};
    await assert.rejects(org1('PublishRelease', ref), /FORBIDDEN/);
    await publish('PublishRelease', ref);
    await assert.rejects(publish('PublishRelease', {...ref, manifest_sha256: 'b'.repeat(64)}), /RELEASE_CONFLICT/);
    await publish('RevokeRelease', ref);
    await assert.rejects(publish('PublishRelease', ref), /RELEASE_CONFLICT/);
    await publish('PublishRelease', {...ref, version: 2});
    await assert.rejects(publish('PublishRelease', ref), /RELEASE_ROLLBACK/);
    assert.equal((await org1('ReadRelease', 'campus', 'knowledge', 'rules')).version, 2);
});

test('audit batches are immutable, contiguous and authorized per stream', async () => {
    const { call, org1 } = fixture();
    const anchor = batch => call('Org1MSP', 'auditor', 'AnchorAudit', batch);
    const first = {stream: 'a', first_seq: 1, last_seq: 3, root: digest};
    await assert.rejects(call('Org2MSP', 'auditor', 'AnchorAudit', first), /FORBIDDEN/);
    await assert.rejects(anchor({...first, first_seq: 2}), /AUDIT_RANGE_INVALID/);
    assert.deepEqual(await anchor(first), first);
    assert.deepEqual(await anchor(first), first);
    await assert.rejects(anchor({...first, root: 'c'.repeat(64)}), /AUDIT_CONFLICT/);
    await assert.rejects(anchor({...first, first_seq: 3, last_seq: 5}), /AUDIT_RANGE_INVALID/);
    await anchor({...first, first_seq: 4, last_seq: 5});
    assert.deepEqual(await org1('ReadAudit', 'a', '1'), first);
    assert.deepEqual(await org1('ReadAuditHead', 'a'), {last_seq: 5});
});
