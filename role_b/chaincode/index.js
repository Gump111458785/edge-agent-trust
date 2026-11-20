const shim = require('fabric-shim');
const { invoke } = require('./ledger');

shim.start({
    async Init() {
        return shim.success();
    },
    async Invoke(stub) {
        const { fcn, params } = stub.getFunctionAndParameters();
        try {
            const result = await invoke(stub, new shim.ClientIdentity(stub), fcn, params);
            return shim.success(Buffer.from(JSON.stringify(result)));
        } catch (error) {
            return shim.error(error.message);
        }
    },
});
