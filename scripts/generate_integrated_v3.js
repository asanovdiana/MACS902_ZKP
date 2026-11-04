const { buildEddsa, buildPoseidon } = require("circomlibjs");
const crypto = require("crypto");
const fs = require("fs");

async function main() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  const credentialSecret = BigInt(
        "0x" + crypto.randomBytes(31).toString("hex")
  );

const credentialSalt = BigInt(
   "0x" + crypto.randomBytes(31).toString("hex")
);

const commitment = F.toObject(
   poseidon([credentialSecret, credentialSalt])
);


const privateKey = crypto.randomBytes(32);
const publicKey = eddsa.prv2pub(privateKey);
const signature = eddsa.signPoseidon(
          privateKey,
          poseidon.F.e(commitment)
);


const hash = (a, b) =>
   F.toObject(poseidon([BigInt(a), BigInt(b)]));

const sibling = 11n;
const otherBranch = hash(33n, 44n);
const firstLevel = hash(sibling, commitment);
const root = hash(firstLevel, otherBranch);

const input = {
    credentialSecret: credentialSecret.toString(),
    credentialSalt: credentialSalt.toString(),
    role: 2,
    clearance: 2,
    deviceComplaint: 1,
    employeeActive: 1,
    Ax: F.toObject(publicKey[0]).toString(),
    Ay: F.toObject(publicKey[1]).toString(),
    R8x: F.toObject(signature.R8[0]).toString(),
    R8y: F.toObject(signature.R8[1]).toString(),
    S: signature.S.toString(),
    M: commitment.toString(),
    leaf: commitment.toString(),
    pathElements: [
       sibling.toString(),
       otherBranch.toString()
   ],
   pathIndices: [1, 0],
   root: root.toString()
};

fs.mkdirSync("tests", { recursive: true });
fs.writeFileSync(
       "tests/integrated_v3_valid.json",
       JSON.stringify(input, null, 2),
       { mode: 0o600 }
    );

  console.log("V3 test input generated successfully!");
  console.log("Credential commitment:", commitment.toString());
}

main().catch(err => {
       console.error(err);
       process.exitCode = 1;
});
