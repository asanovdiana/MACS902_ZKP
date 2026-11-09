pragma circom 2.2.3;

// TEST MAIN (G1-S1-CIRC-031): AttributeHash alone; attrHash is the only public signal.
include "../../components/attribute_hash.circom";

component main = AttributeHash();
