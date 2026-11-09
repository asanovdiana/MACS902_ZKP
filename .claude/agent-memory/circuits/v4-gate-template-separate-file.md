# v4 template lives outside the main file

circom 2.2.3 refuses to include a file that declares `component main` ("Here it is another main
component"), so the depth-8/20 benchmark mains cannot include `integrated_access_v4.circom`. The
template `IntegratedAccessGateV4(depth)` is in `circuits/components/integrated_access_v4_gate.circom`
and all three mains (`integrated_access_v4{,_d8,_d20}.circom`) are 3-line includes. Mutation targets
and test build source lists must name the gate file, not just the main (the main has 0 sites).
See [[v4-constraint-counts]], [[v4-gate-one-row-recipes]].
