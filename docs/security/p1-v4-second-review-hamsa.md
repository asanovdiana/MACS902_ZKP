# P1 V4 Circuit — Second Security Review

**Project:** MACS902 Zero-Knowledge Proof Access Gate  
**Reviewer:** Hamsa Devanand
**Review date:** 23 November 2026  
**Branch:** `feature/p1-v4-review-hamsa`  
**Review type:** Source-code inspection and automated test execution

## 1. Review Objective

The objective of this review was to examine the V4 integrated access circuit and its supporting components, assess whether the implemented constraints reflect the documented security requirements, and record the results of automated testing.

The review focused on credential attribute integrity, issuer signature verification, Merkle membership, access-policy enforcement, credential expiry, and challenge binding.

## 2. Files Reviewed

The following files were inspected:

- `circuits/integrated_access_v4.circom`
- `circuits/components/integrated_access_v4_gate.circom`
- `circuits/components/access_policy_v4.circom`
- `circuits/components/attribute_hash.circom`
- `circuits/components/expiry.circom`
- `circuits/components/challenge_binding.circom`
- `circuits/components/eddsa_verifier.circom`
- `circuits/components/issuer_key.circom`
- `circuits/components/merkle_membership_n.circom`

## 3. Security Review Findings

### 3.1 Integrated Access Circuit

The V4 main circuit instantiates `IntegratedAccessGateV4(16)`, using a Merkle-tree depth of 16.

The integrated gate connects the credential commitment, attribute hash, issuer signature verification, elliptic-curve checks, Merkle membership, access policy, expiry validation, and challenge binding.

The issuer public key is exposed through public signals and is connected to both the signature verifier and the elliptic-curve validation component.

**Finding:** The examined wiring is consistent with the documented V4 access-control statement. The application must still validate the public signals against its trusted authorization context.

### 3.2 Credential Attribute Integrity

`AttributeHash` uses `Poseidon(7)` to hash the role, department, clearance, device-compliance status, employee status, expiry, and credential commitment.

The component constrains role, department, and clearance to two-bit values. Device compliance and employee status are constrained to Boolean values.

The integrated gate uses the calculated attribute hash as both the issuer-signed message and the Merkle leaf.

**Finding:** The examined constraints support attribute integrity and bind the credential attributes to signature and membership verification.

### 3.3 Issuer Signature and Public-Key Validation

`IssuerSignatureCheck` enables Circomlib's `EdDSAPoseidonVerifier` and connects the issuer public key, signature values, and attribute hash.

`SignaturePointsOnCurve` uses `BabyCheck` to validate the issuer public-key point and the signature's R8 point on BabyJubJub.

**Finding:** The examined implementation provides signature verification and on-curve validation. The gateway must independently ensure that the public issuer key matches the trusted issuer. The on-curve component does not independently establish subgroup membership.

### 3.4 Merkle Membership

`MerkleMembershipN` checks the Merkle authentication path using Poseidon hashing.

Each path index is constrained to a Boolean value, and the calculated final hash must equal the public Merkle root.

The integrated gate uses the calculated credential attribute hash as the leaf.

**Finding:** The examined constraints implement the intended Merkle membership check. The application must ensure that the public root is trusted and current. The treatment of zero-valued leaves is a documented edge case that warrants consideration.

### 3.5 Access Policy

`AccessPolicyV4` checks:

- Whether the role is permitted by the public role mask.
- Whether the department is permitted by the public department mask.
- Whether clearance meets the required minimum.
- Whether device compliance is satisfied when required.
- Whether the employee is active.

Role, department, clearance, and relevant policy inputs are range-constrained.

**Finding:** The examined constraints are consistent with the documented access-policy requirements.

### 3.6 Credential Expiry

`ExpiryCheck` constrains both `now` and `expiry` to 64-bit unsigned values and requires `now < expiry`.

**Finding:** The circuit rejects credentials at or beyond their expiry time, provided the gateway supplies the correct trusted current-time value.

### 3.7 Challenge Binding and Nullifier

`ChallengeBinding` derives:

`nullifier = Poseidon(credentialSecret, resourceId, epoch)`

It also introduces a quadratic constraint involving the public nonce.

**Finding:** The component implements the documented nullifier derivation and includes the nonce in a circuit constraint. However, it does not independently prove that the nonce was issued by the gateway or that the epoch and resource identifier are valid.

The gateway remains responsible for challenge validation, public-signal comparison, and replay prevention.

## 4. Automated Testing

The following command was executed in the WSL development environment:

`./node_modules/.bin/mocha circuits/test/v4.test.js --timeout 120000`

**Observed results:**

- Passing: 895
- Pending: 1
- Failing: 0
- Execution time: approximately 7 minutes

The terminal output also included Merkle membership constraint checks and tests documenting known V3 security gaps.

The test run completed without reported failures. The pending test should not be described as a passing test.

These results provide automated testing evidence but do not constitute a complete formal security proof or production security certification.

## 5. Residual Risks and External Dependencies

The review identified the following important boundaries:

1. The gateway must pin and validate the trusted issuer public key.
2. The gateway must validate the trusted Merkle root and its freshness.
3. The gateway must validate the nonce, resource identifier, current time, and epoch against its issued challenge.
4. The gateway must implement replay protection using appropriate nullifier and nonce tracking.
5. The issuer-key on-curve component does not independently perform every possible elliptic-curve subgroup check.
6. Zero-valued Merkle leaves remain a documented edge case for consideration.
7. The review did not establish that a final multi-party trusted setup ceremony had been completed.

## 6. Review Conclusion

Based on the inspected source code, the V4 circuit's wiring and security constraints appear consistent with its documented access-control design.

The automated test run completed with 895 passing tests, one pending test, and zero reported failures.

No definite new circuit vulnerability was established during this review. However, end-to-end security depends on correct gateway validation, trusted public inputs, key management, and completion of the required setup procedures.

This review records the source-code inspection and observed testing evidence. It does not claim a formal audit or independent verification of every system component.

**Review status:** Source-code inspection and automated test execution completed. Documentation prepared for team review.
