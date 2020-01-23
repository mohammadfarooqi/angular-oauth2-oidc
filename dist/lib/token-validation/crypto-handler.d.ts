/**
 * Abstraction for crypto algorithms
*/
export declare abstract class CryptoHandler {
    abstract calcHash(valueToHash: string, algorithm: string): Promise<string>;
}
