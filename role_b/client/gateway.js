const fs = require('node:fs');
const path = require('node:path');
const { createPrivateKey } = require('node:crypto');
const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');

async function submit(configFile, transaction, args) {
    const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    const { channel, chaincode, identity, peers } = config;
    if (peers.length !== 2 || peers[0].msp_id !== 'Org1MSP' || peers[1].msp_id !== 'Org2MSP'
        || peers[0].endpoint === peers[1].endpoint || peers[0].server_name === peers[1].server_name
        || !peers.some(peer => peer.msp_id === identity.msp_id)) {
        throw new Error('Expected separate Org1MSP and Org2MSP peers');
    }
    const read = file => fs.readFileSync(path.resolve(path.dirname(configFile), file));
    const credentials = read(identity.certificate);
    const signer = signers.newPrivateKeySigner(createPrivateKey(read(identity.private_key)));
    const clients = [];
    const gateways = [];
    try {
        for (const peer of peers) {
            const client = new grpc.Client(peer.endpoint, grpc.credentials.createSsl(read(peer.tls_root)), {
                'grpc.ssl_target_name_override': peer.server_name,
                'grpc.default_authority': peer.server_name,
            });
            clients.push(client);
            gateways.push(connect({
                client,
                identity: {mspId: identity.msp_id, credentials},
                signer,
                endorseOptions: () => ({deadline: Date.now() + 3000}),
                submitOptions: () => ({deadline: Date.now() + 2000}),
                commitStatusOptions: () => ({deadline: Date.now() + 5000}),
            }));
        }
        const primary = peers.findIndex(peer => peer.msp_id === identity.msp_id);
        const contract = gateways[primary].getNetwork(channel).getContract(chaincode);
        const proposal = contract.newProposal(transaction, {
            arguments: args,
            endorsingOrganizations: peers.map(peer => peer.msp_id),
        });
        const endorsed = await proposal.endorse();
        const transactionId = proposal.getTransactionId();
        if (endorsed.getTransactionId() !== transactionId) throw new Error('Endorsement transaction mismatch');
        const submitted = await endorsed.submit();
        const confirmation = gateways[1 - primary].newCommit(submitted.getBytes());
        const [first, second] = await Promise.all([submitted.getStatus(), confirmation.getStatus()]);
        if (!first.successful || !second.successful || first.blockNumber !== second.blockNumber
            || first.transactionId !== transactionId || second.transactionId !== transactionId) {
            throw new Error(`Commit verification failed (${first.code}, ${second.code})`);
        }
        return {transaction_id: transactionId, block: first.blockNumber.toString(),
            value: JSON.parse(Buffer.from(submitted.getResult()).toString('utf8'))};
    } finally {
        gateways.forEach(gateway => gateway.close());
        clients.forEach(client => client.close());
    }
}

const [configFile, transaction, ...args] = process.argv.slice(2);
submit(configFile, transaction, args).then(result => console.log(JSON.stringify(result))).catch(error => {
    console.error(error.message);
    process.exitCode = 1;
});
