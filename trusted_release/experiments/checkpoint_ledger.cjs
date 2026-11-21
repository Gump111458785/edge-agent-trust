// Test transport only: execute B's unchanged chaincode with an in-memory Fabric stub.
// The receipt below is simulated, and is never described as a live Fabric commit.
const fs = require('node:fs');
const crypto = require('node:crypto');
const {invoke} = require('../../role_b/chaincode/ledger.js');

async function main() {
    const commands = JSON.parse(fs.readFileSync(0, 'utf8'));
    const state = new Map();
    let block = 0;
    const stub = {
        getState: async key => state.get(key) ?? Buffer.alloc(0),
        putState: async (key, value) => state.set(key, value),
        createCompositeKey: (name, parts) => JSON.stringify([name, ...parts]),
        getChannelID: () => 'roleb',
        getTxTimestamp: () => ({seconds: BigInt(1700000000)}),
        getTxID: () => crypto.createHash('sha256').update(String(block)).digest('hex'),
    };
    let value;
    for (const command of commands) {
        block += 1;
        const role = command.transaction === 'ReadRelease' ? 'reader' : 'publisher';
        const identity = {getMSPID: () => 'Org2MSP', assertAttributeValue: (_, expected) => expected === role};
        value = await invoke(stub, identity, command.transaction, command.args);
    }
    process.stdout.write(JSON.stringify({transaction_id: stub.getTxID(), block: String(block), value}));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
