declare module 'snarkjs' {
  export const groth16: {
    verify(
      vkey: unknown,
      publicSignals: string[],
      proof: unknown,
      logger?: unknown,
    ): Promise<boolean>;
    fullProve(
      input: unknown,
      wasm: string,
      zkey: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
  };
  export const r1cs: {
    info(
      file: string,
      logger?: unknown,
    ): Promise<{ nConstraints: number; nPrvInputs: number; nPubInputs: number; nOutputs: number }>;
  };
}
declare module 'circomlibjs';
