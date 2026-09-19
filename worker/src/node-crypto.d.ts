// Minimal typing for the one Node API we use (available via nodejs_compat).
// Avoids pulling in all of @types/node.
declare module "node:crypto" {
  interface Hash {
    update(data: Uint8Array | string): Hash;
    digest(encoding: "hex" | "base64"): string;
    digest(): Uint8Array;
  }
  export function createHash(algorithm: string): Hash;
}
