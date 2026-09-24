/* eslint-disable prefer-promise-reject-errors */
export const greater_than_zero = input => {
  return input > 0;
};

export const privkey = input => {
  return (
    input.length === 0 || (/^[0-9A-Fa-f]+$/.test(input) && input.length == 64)
  );
};

export const master_node_key = input => {
  return input.length === 64 && /^[0-9A-Za-z]+$/.test(input);
};

export const bchat_id = input => {
  return input.length === 66 && /^bd[0-9A-Za-z]+$/.test(input);
};

// shortened Belnet BNS name
export const belnet_name = (input, beldexExt = false) => {
  let inputSafe = input || "";
  let maxLength = 32;

  if (inputSafe.includes("-")) {
    maxLength = 63;
  }

  let dashRule = !(
    inputSafe.length > 4 &&
    inputSafe.slice(2, 4) === "--" &&
    !(inputSafe.slice(0, 2) === "xn")
  );

  let reservedNames = ["localhost", "beldex", "mnode"];
  let regexCheck;
  if (beldexExt) {
    regexCheck = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?.bdx$/.test(inputSafe);
  } else {
    regexCheck = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(inputSafe);
  }
  return (
    inputSafe.length <= maxLength &&
    dashRule &&
    !reservedNames.includes(inputSafe) &&
    regexCheck
  );
};

export const bchat_name_or_belnet_name = input => {
  const lcInput = input.toLowerCase();
  return bchat_name(lcInput) || belnet_name(lcInput, true);
};

// Full belnet address
export const belnet_address = input => {
  return (
    input.length === 52 &&
    /^[ybndrfg8ejkmcpqxot1uwisza345h769]{51}[yo]$/.test(input)
  );
};

export const bchat_name = input => {
  return (
    input.length === 0 ||
    /^[a-z0-9_]([a-z0-9-_]*[a-z0-9_])?$/.test(input.toLowerCase())
  );
};
export const bns_name = input => {
  return (
    input.length === 0 ||
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(input.toLowerCase())
  );
};

export const eth_address = input => {
  return /^(0x)?[0-9a-fA-F]{40}$/.test(input);
};

// Addresses already confirmed valid by wallet-rpc (validity never changes)
const validAddresses = new Set();
// In-flight checks, so concurrent validators share one RPC call
const pendingChecks = new Map();

const checkAddress = (input, gateway) => {
  if (validAddresses.has(input)) return Promise.resolve(true);
  let pending = pendingChecks.get(input);
  if (pending) return pending;

  pending = new Promise(resolve => {
    const finish = valid => {
      clearTimeout(timer);
      gateway.removeListener("validate_address", onResult);
      pendingChecks.delete(input);
      if (valid) validAddresses.add(input);
      resolve(valid);
    };
    // Responses carry the address, so each check only takes its own answer
    const onResult = data => {
      if (data.address === input) finish(!!data.valid);
    };
    const timer = setTimeout(() => finish(false), 15000);
    gateway.on("validate_address", onResult);
    gateway.send("wallet", "validate_address", {
      address: input
    });
  });
  pendingChecks.set(input, pending);
  return pending;
};

export const address = (input, gateway) => {
  // Validate the address
  if (input.toLowerCase().endsWith(".bdx")) {
    return Promise.resolve();
  }
  // Standard, sub- and integrated addresses are 95-106 base58 characters;
  // anything else can be rejected without asking wallet-rpc.
  if (
    !/^[0-9A-Za-z]+$/.test(input) ||
    input.length < 95 ||
    input.length > 106
  ) {
    return Promise.reject();
  }
  return checkAddress(input, gateway).then(valid =>
    valid ? undefined : Promise.reject()
  );
};
