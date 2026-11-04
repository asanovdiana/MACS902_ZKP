pragma circom 2.2.3;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template MerkleMembership() {
     signal input leaf;
     signal input pathElements[2];
     signal input pathIndices[2];
     signal input root;

     signal hashes[3];
     signal left[2];
     signal right[2];

     component hashers[2];

     hashes[0] <== leaf;

   for (var i = 0; i < 2; i++) {
      pathIndices[i] * (pathIndices[i] -1) === 0;

         left[i] <==
            hashes[i] + pathIndices[i] *
            (pathElements[i] - hashes[i]);

         right[i] <==
           pathElements[i] + pathIndices[i] *
           (hashes[i] - pathElements[i]);

         hashers[i] = Poseidon(2);

         hashers[i].inputs[0] <== left[i];
         hashers[i].inputs[1] <== right[i];

             hashes[i + 1] <== hashers[i].out;
   }

    hashes[2] === root;
}
