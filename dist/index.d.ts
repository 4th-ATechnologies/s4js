/**
 * This is a wrapper for the S4 encryption library:
 * https://github.com/4th-ATechnologies/S4
 *
 * ---- IMPORTANT -----
 *
 * This code was written in Typescript, and compiled to Javascript.
 * I highly recommend reading the original Typescript, rather than the compiled version.
 *
 * The Typescript is much easier to read (because, you know, it actually has type information).
**/
export declare type EmscriptenJavascriptType = "number" | "string" | "array" | "boolean" | null;
export declare type LlvmIrType = "i8" | "i16" | "i32" | "i64" | "float" | "double" | "*";
export interface EmscriptenModule {
    HEAPU8: Uint8Array;
    _malloc: (numBytes: number) => number;
    _free: (ptr: number) => void;
    ccall: (ident: string, returnType: EmscriptenJavascriptType, argTypes: EmscriptenJavascriptType[], args: any[]) => any;
    setValue: (ptr: number, value: any, type: LlvmIrType) => void;
    getValue: (ptr: number, type: LlvmIrType) => number;
    UTF8ToString: (ptr: number) => string;
}
export interface S4Module extends EmscriptenModule {
    _S4_Init: () => S4Err;
}
export declare enum S4Err {
    NoErr = 0,
    NOP = 1,
    UnknownError = 2,
    BadParams = 3,
    OutOfMemory = 4,
    BufferTooSmall = 5,
    UserAbort = 6,
    UnknownRequest = 7,
    LazyProgrammer = 8,
    AssertFailed = 9,
    FeatureNotAvailable = 10,
    ResourceUnavailable = 11,
    NotConnected = 12,
    ImproperInitialization = 13,
    CorruptData = 14,
    SelfTestFailed = 15,
    BadIntegrity = 16,
    BadHashNumber = 17,
    BadCipherNumber = 18,
    BadPRNGNumber = 19,
    SecretsMismatch = 20,
    KeyNotFound = 21,
    ProtocolError = 22,
    ProtocolContention = 23,
    KeyLocked = 24,
    KeyExpired = 25,
    EndOfIteration = 26,
    OtherError = 27,
    PubPrivKeyNotFound = 28,
    NotEnoughShares = 29,
    PropertyNotFound = 30
}
export declare enum S4HashAlgorithm {
    MD5 = 1,
    SHA1 = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
    SKEIN256 = 7,
    SKEIN512 = 8,
    SKEIN1024 = 9,
    SHA512_256 = 10,
    xxHash32 = 20,
    xxHash64 = 21,
    SHA3_224 = 30,
    SHA3_256 = 31,
    SHA3_384 = 32,
    SHA3_512 = 33
}
export declare enum S4CipherAlgorithm {
    AES128 = 1,
    AES192 = 2,
    AES256 = 3,
    "2FISH256" = 4,
    TWOFISH256 = 4,
    "3FISH256" = 100,
    THREEFISH256 = 100,
    "3FISH512" = 102,
    THREEFISH512 = 102,
    "3FISH1024" = 103,
    THREEFISH1024 = 103,
    SharedKey = 200,
    ECC384 = 300,
    ECC41417 = 301
}
export declare enum S4Property {
    KeyType = "keyType",
    KeySuite = "keySuite",
    HashAlgorithm = "hashAlgorithm",
    KeyData = "keyData",
    KeyID = "keyID",
    KeyIDString = "keyID-String",
    Mac = "mac",
    StartDate = "start-date",
    ExpireDate = "expire-date",
    EncryptedKey = "encrypted",
    Encoding = "encoding",
    Signature = "signature",
    SignedBy = "issuer",
    SignedProperties = "signed-properties",
    SignableProperties = "signable-properties",
    SignedDate = "issue-date",
    SigExpire = "sig-expire",
    SigID = "sigID"
}
export declare class S4 {
    static load(module: any): S4 | null;
    /**
     * Any method that could potentially return an error is typed to convey the presence of an error to you.
     * For example:
     *
     * - hash_do(...): Uint8Array|null
     * - hash_init(...): number|null
     *
     * The hash_do() method will return null if an error occurs.
     * Similarly the hash_init() method will return null if an error occurs.
     *
     * This is standardized to prevent any confusion:
     * - Methods that are expected to return a value will return null in the case of an error.
     *
     * Whenever one of these methods returns null, you can get the error code via this property.
     *
     * For methods that are NOT expected to return a value, we simply return the error directly.
     * - hash_update(...): S4Err
     *
     * Even for methods like hash_update, this property will store the most recent error.
     * I.e. this property will match the S4Err returned from hash_update() after calling that function.
     *
     * You can also get a human-redable version of the error code via the err_str() function.
    **/
    err_code: S4Err;
    private module;
    private constructor();
    /**
     * Utility method.
     *
     * The `ccall` method takes `argTypes` & `args` as separate arrays.
     * This has lead to bugs wherein the 2 arrays didn't match.
     *
     * This method combines the argType & arg as a tuple,
     * and adds strong typing to prevent bugs.
    **/
    private ccall_wrapper;
    /**
     * ----- General -----
    **/
    version(): string;
    /**
     * Converts the given `err_code` to a human-readable string.
     * If no `err_code` is passed, uses this.err_code automatically.
    **/
    err_str(in_err_code?: number): string;
    /**
     * ----- Hashing -----
     *
     * A bunch of different hash algorithms are supported.
     * Regardless of which hash algorithm you use, the API is the same.
     *
     * The easy way:
     *
     * | let hash = s4.hash_do(S4HashAlgorithm.someHashAlgo, yourDataToHashHere)
     * | if (hash == null)
     * |   console.log("s4.hash_do(): err: "+ s4.err_code)
     * | else
     * |    console.log("hash: "+ s4.util_hexString(hash))
     *
     * The streaming way:
     *
     * | let context = s4.hash_init(S4HashAlgorithm.someHashAlgo)
     * | for (const chunk of chunks) {
     * |   s4.hash_update(context, chunk)
     * | }
     * | let hash = s4.hash_final(context)
     * | s4.hash_free(context) // <= don't leak memory
    **/
    /**
     * Performs a hash in one step.
     * If null is returned, check err_code/err_str for more information.
    **/
    hash_do(algorithm: S4HashAlgorithm, data: Readonly<Uint8Array>): Uint8Array | null;
    hash_getSizeInBits(algorithm: S4HashAlgorithm): number;
    hash_algorithmIsAvailable(algorithm: S4HashAlgorithm): boolean;
    hash_init(algorithm: S4HashAlgorithm): number | null;
    hash_getSize(context: number): number;
    hash_update(context: number, data: Readonly<Uint8Array>): S4Err;
    hash_final(context: number): Uint8Array | null;
    hash_reset(context: number): S4Err;
    hash_free(context: number): void;
    /**
     * ----- General: Cipher -----
     *
    **/
    /**
     * Returns the "size" of the cipher key (in bits).
     *
     * For example, AES256 will return 256 bits.
     * This means the key will be: 256 / 8 = 32 bytes.
    **/
    cipher_getKeySizeInBits(algorithm: S4CipherAlgorithm): number;
    /**
     * Returns the size of the block the cipher operates on (in bytes).
    **/
    cipher_getBlockSize(algorithm: S4CipherAlgorithm): number;
    cipher_algorithmIsAvailable(algorithm: S4CipherAlgorithm): boolean;
    /**
     * ----- Cipher Mode: Electronic Codebook (ECB) -----
     *
     * Note:
     *   ECB mode is fine for encrypting a single block,
     *   but not well-designed for encrypting multiple blocks:
     *
     *   https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)
    **/
    ecb_encrypt(options: {
        algorithm: S4CipherAlgorithm;
        key: Readonly<Uint8Array>;
        input: Readonly<Uint8Array>;
    }): Uint8Array | null;
    ecb_decrypt(options: {
        algorithm: S4CipherAlgorithm;
        key: Readonly<Uint8Array>;
        input: Readonly<Uint8Array>;
    }): Uint8Array | null;
    /**
     * ----- Cipher Mode: Cipher Block Chaining (CBC) -----
    **/
    cbc_init(options: {
        algorithm: S4CipherAlgorithm;
        key: Readonly<Uint8Array>;
        iv: Readonly<Uint8Array>;
    }): number | null;
    cbc_getAlgorithm(context: number): S4CipherAlgorithm | null;
    cbc_encrypt(context: number, input: Readonly<Uint8Array>): Uint8Array | null;
    cbc_decrypt(context: number, input: Readonly<Uint8Array>): Uint8Array | null;
    cbc_free(context: number): void;
    cbc_encryptPad(options: {
        algorithm: S4CipherAlgorithm;
        key: Readonly<Uint8Array>;
        iv: Readonly<Uint8Array>;
        input: Readonly<Uint8Array>;
    }): Uint8Array | null;
    cbc_decryptPad(options: {
        algorithm: S4CipherAlgorithm;
        key: Readonly<Uint8Array>;
        iv: Readonly<Uint8Array>;
        input: Readonly<Uint8Array>;
    }): Uint8Array | null;
    /**
     * ----- Tweakable Block Cipher -----
    **/
    /**
     * Initializes a Tweakable Block Cipher context.
     *
     * The key.byteLength should be appropriate for the given algorithm.
     * You can use cipher_getSize(algorithm) to determine the length dynamically.
    **/
    tbc_init(algorithm: S4CipherAlgorithm, key: Readonly<Uint8Array>): number | null;
    tbc_setTweek(context: number, tweek: Readonly<Uint8Array>): S4Err;
    tbc_encrypt(context: number, data: Readonly<Uint8Array>): Uint8Array | null;
    tbc_decrypt(context: number, data: Readonly<Uint8Array>): Uint8Array | null;
    tbc_free(context: number): void;
    /**
     * ----- Elliptic-curve cryptography -----
    **/
    ecc_init(): number | null;
    ecc_generate(context: number, keySize: number): S4Err;
    ecc_import(context: number, data: Readonly<Uint8Array>): S4Err;
    ecc_export(context: number, includePrivateKey: boolean): Uint8Array | null;
    /**
     * Returns whether or not the ECC key is a private key.
     * Generally this method is used when importing key material,
     * and you want to find ensure the imported key material is a private key,
     * as opposed to just a public key.
    **/
    ecc_isPrivate(context: number): boolean;
    ecc_free(context: number): void;
    /**
     * ----- Key Wrappers -----
    **/
    key_deserializeKey(key: Readonly<Uint8Array>): number | null;
    key_newTBC(algorithm: S4CipherAlgorithm, key: Readonly<Uint8Array>): number | null;
    /**
     * Key "wrapping" refers to the technique of taking an encryption key,
     * and encrypting it using some other technique, such as a different encryption key.
     *
     * Here's a common example:
     * You have a symmetric key that you've used to encrypt a big file.
     * Now you want to send the symmetric key to somebody else,
     * and you have the other person's public key. So what you do is "wrap"
     * the symmetric key using the public key. That is, you encrypt the
     * symmetric key itself using the public key to perform the encryption.
     *
     * In the above example:
     * - context_outer: This is the other user's public key.
     * - context_inner: This is the symmetric encryption key you want to wrap.
     *
     * @param context_outer
     * 	The encryption key that will be used to encrypt the context_inner.
     *
     * @param context_inner
     * 	The key you want to wrap.
     * 	That is, this key will be encrypted.
    **/
    key_wrapToKey(context_outer: number, context_inner: number): Uint8Array | null;
    key_getProperty(context: number, property: S4Property): any | null;
    key_free(context: number): void;
    /**
     * ----- Internal Utilities -----
    **/
    private heap_copyBuffer;
    /**
     * ----- Javascript Utilities -----
    **/
    util_concatBuffers(buffers: Array<Readonly<Uint8Array>>): Uint8Array;
    util_compareBuffers(bufferA: Readonly<Uint8Array>, bufferB: Readonly<Uint8Array>): boolean;
    util_hexString(buffer: Readonly<Uint8Array>): string;
}
//# sourceMappingURL=index.d.ts.map