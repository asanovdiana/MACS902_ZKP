pragma circom 2.2.3;

include "./components/access_policy.circom";
include "./components/eddsa_verifier.circom";
include "./components/merkle_membership.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template IntegratedAccessGate() {
  signal input credentialSecret;
  signal input credentialSalt;
component commitmentHasher = Poseidon(2);

commitmentHasher.inputs[0] <== credentialSecret;
commitmentHasher.inputs[1] <== credentialSalt;

signal credentialCommitment;
credentialCommitment <== commitmentHasher.out;

  signal input role;
  signal input clearance;
  signal input deviceCompliant;
  signal input employeeActive;

 signal input Ax;
 signal input Ay;
 signal input R8x;
 signal input R8y;
 signal input S;
 signal input M;

signal input leaf;
signal input pathElements[2];
signal input pathIndices[2];
signal input root;
M === credentialCommitment;
leaf === credentialCommitment;

component policy = FileShareAccess();

policy.role <== role;
policy.clearance <== clearance;
  policy.deviceCompliant <== deviceCompliant;
policy.employeeActive <== employeeActive;
  deviceCompliant * (deviceCompliant - 1) === 0;
employeeActive * (employeeActive - 1) === 0;

component signature = IssuerSignatureCheck();

signature.Ax <== Ax;
signature.Ay <== Ay;
signature.R8x <== R8x;
signature.R8y <== R8y;
signature.S <== S;
signature.M <== M;

component merkle = MerkleMembership();

merkle.leaf <== leaf;
merkle.root <== root;

for (var i= 0; i < 2; i++) {
   merkle.pathElements[i] <== pathElements[i];
   merkle.pathIndices[i] <== pathIndices[i];
  }
}

component main {public [root]} = IntegratedAccessGate();
