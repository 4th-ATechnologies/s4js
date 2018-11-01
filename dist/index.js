"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
var S4Err;
(function (S4Err) {
    S4Err[S4Err["NoErr"] = 0] = "NoErr";
    S4Err[S4Err["NOP"] = 1] = "NOP";
    S4Err[S4Err["UnknownError"] = 2] = "UnknownError";
    S4Err[S4Err["BadParams"] = 3] = "BadParams";
    S4Err[S4Err["OutOfMemory"] = 4] = "OutOfMemory";
    S4Err[S4Err["BufferTooSmall"] = 5] = "BufferTooSmall";
    S4Err[S4Err["UserAbort"] = 6] = "UserAbort";
    S4Err[S4Err["UnknownRequest"] = 7] = "UnknownRequest";
    S4Err[S4Err["LazyProgrammer"] = 8] = "LazyProgrammer";
    S4Err[S4Err["AssertFailed"] = 9] = "AssertFailed";
    S4Err[S4Err["FeatureNotAvailable"] = 10] = "FeatureNotAvailable";
    S4Err[S4Err["ResourceUnavailable"] = 11] = "ResourceUnavailable";
    S4Err[S4Err["NotConnected"] = 12] = "NotConnected";
    S4Err[S4Err["ImproperInitialization"] = 13] = "ImproperInitialization";
    S4Err[S4Err["CorruptData"] = 14] = "CorruptData";
    S4Err[S4Err["SelfTestFailed"] = 15] = "SelfTestFailed";
    S4Err[S4Err["BadIntegrity"] = 16] = "BadIntegrity";
    S4Err[S4Err["BadHashNumber"] = 17] = "BadHashNumber";
    S4Err[S4Err["BadCipherNumber"] = 18] = "BadCipherNumber";
    S4Err[S4Err["BadPRNGNumber"] = 19] = "BadPRNGNumber";
    S4Err[S4Err["SecretsMismatch"] = 20] = "SecretsMismatch";
    S4Err[S4Err["KeyNotFound"] = 21] = "KeyNotFound";
    S4Err[S4Err["ProtocolError"] = 22] = "ProtocolError";
    S4Err[S4Err["ProtocolContention"] = 23] = "ProtocolContention";
    S4Err[S4Err["KeyLocked"] = 24] = "KeyLocked";
    S4Err[S4Err["KeyExpired"] = 25] = "KeyExpired";
    S4Err[S4Err["EndOfIteration"] = 26] = "EndOfIteration";
    S4Err[S4Err["OtherError"] = 27] = "OtherError";
    S4Err[S4Err["PubPrivKeyNotFound"] = 28] = "PubPrivKeyNotFound";
    S4Err[S4Err["NotEnoughShares"] = 29] = "NotEnoughShares";
    S4Err[S4Err["PropertyNotFound"] = 30] = "PropertyNotFound";
})(S4Err = exports.S4Err || (exports.S4Err = {}));
;
var S4HashAlgorithm;
(function (S4HashAlgorithm) {
    S4HashAlgorithm[S4HashAlgorithm["MD5"] = 1] = "MD5";
    S4HashAlgorithm[S4HashAlgorithm["SHA1"] = 2] = "SHA1";
    S4HashAlgorithm[S4HashAlgorithm["SHA224"] = 3] = "SHA224";
    S4HashAlgorithm[S4HashAlgorithm["SHA256"] = 4] = "SHA256";
    S4HashAlgorithm[S4HashAlgorithm["SHA384"] = 5] = "SHA384";
    S4HashAlgorithm[S4HashAlgorithm["SHA512"] = 6] = "SHA512";
    S4HashAlgorithm[S4HashAlgorithm["SKEIN256"] = 7] = "SKEIN256";
    S4HashAlgorithm[S4HashAlgorithm["SKEIN512"] = 8] = "SKEIN512";
    S4HashAlgorithm[S4HashAlgorithm["SKEIN1024"] = 9] = "SKEIN1024";
    S4HashAlgorithm[S4HashAlgorithm["SHA512_256"] = 10] = "SHA512_256";
    S4HashAlgorithm[S4HashAlgorithm["xxHash32"] = 20] = "xxHash32";
    S4HashAlgorithm[S4HashAlgorithm["xxHash64"] = 21] = "xxHash64";
    S4HashAlgorithm[S4HashAlgorithm["SHA3_224"] = 30] = "SHA3_224";
    S4HashAlgorithm[S4HashAlgorithm["SHA3_256"] = 31] = "SHA3_256";
    S4HashAlgorithm[S4HashAlgorithm["SHA3_384"] = 32] = "SHA3_384";
    S4HashAlgorithm[S4HashAlgorithm["SHA3_512"] = 33] = "SHA3_512";
})(S4HashAlgorithm = exports.S4HashAlgorithm || (exports.S4HashAlgorithm = {}));
;
var S4CipherAlgorithm;
(function (S4CipherAlgorithm) {
    S4CipherAlgorithm[S4CipherAlgorithm["AES128"] = 1] = "AES128";
    S4CipherAlgorithm[S4CipherAlgorithm["AES192"] = 2] = "AES192";
    S4CipherAlgorithm[S4CipherAlgorithm["AES256"] = 3] = "AES256";
    S4CipherAlgorithm[S4CipherAlgorithm["2FISH256"] = 4] = "2FISH256";
    S4CipherAlgorithm[S4CipherAlgorithm["TWOFISH256"] = 4] = "TWOFISH256";
    S4CipherAlgorithm[S4CipherAlgorithm["3FISH256"] = 100] = "3FISH256";
    S4CipherAlgorithm[S4CipherAlgorithm["THREEFISH256"] = 100] = "THREEFISH256";
    S4CipherAlgorithm[S4CipherAlgorithm["3FISH512"] = 102] = "3FISH512";
    S4CipherAlgorithm[S4CipherAlgorithm["THREEFISH512"] = 102] = "THREEFISH512";
    S4CipherAlgorithm[S4CipherAlgorithm["3FISH1024"] = 103] = "3FISH1024";
    S4CipherAlgorithm[S4CipherAlgorithm["THREEFISH1024"] = 103] = "THREEFISH1024";
    S4CipherAlgorithm[S4CipherAlgorithm["SharedKey"] = 200] = "SharedKey";
    S4CipherAlgorithm[S4CipherAlgorithm["ECC384"] = 300] = "ECC384";
    S4CipherAlgorithm[S4CipherAlgorithm["ECC41417"] = 301] = "ECC41417";
})(S4CipherAlgorithm = exports.S4CipherAlgorithm || (exports.S4CipherAlgorithm = {}));
;
var S4Property;
(function (S4Property) {
    S4Property["KeyType"] = "keyType";
    S4Property["KeySuite"] = "keySuite";
    S4Property["HashAlgorithm"] = "hashAlgorithm";
    S4Property["KeyData"] = "keyData";
    S4Property["KeyID"] = "keyID";
    S4Property["KeyIDString"] = "keyID-String";
    S4Property["Mac"] = "mac";
    S4Property["StartDate"] = "start-date";
    S4Property["ExpireDate"] = "expire-date";
    S4Property["EncryptedKey"] = "encrypted";
    S4Property["Encoding"] = "encoding";
    S4Property["Signature"] = "signature";
    S4Property["SignedBy"] = "issuer";
    S4Property["SignedProperties"] = "signed-properties";
    S4Property["SignableProperties"] = "signable-properties";
    S4Property["SignedDate"] = "issue-date";
    S4Property["SigExpire"] = "sig-expire";
    S4Property["SigID"] = "sigID";
})(S4Property = exports.S4Property || (exports.S4Property = {}));
var S4PropertyType;
(function (S4PropertyType) {
    S4PropertyType[S4PropertyType["Invalid"] = 0] = "Invalid";
    S4PropertyType[S4PropertyType["UTF8String"] = 1] = "UTF8String";
    S4PropertyType[S4PropertyType["Binary"] = 2] = "Binary";
    S4PropertyType[S4PropertyType["Time"] = 3] = "Time";
    S4PropertyType[S4PropertyType["Numeric"] = 4] = "Numeric";
})(S4PropertyType || (S4PropertyType = {}));
;
const NUM_BYTES_POINTER = (32 / 8);
const NUM_BYTES_SIZE_T = (32 / 8);
class S4 {
    static load(module) {
        if (module && module._S4_Init) {
            return new S4(module);
        }
        return null;
    }
    constructor(module) {
        this.module = module;
        // As of now, the S4_Init() method will never return an error,
        // despite the fact that the API indicates it could.
        //  (Reserved for potential future changes.)
        // 
        this.err_code = this.module._S4_Init();
        if (this.err_code != S4Err.NoErr) {
            console.log("S4_Init(): err: " + this.err_code);
        }
    }
    /**
     * Utility method.
     *
     * The `ccall` method takes `argTypes` & `args` as separate arrays.
     * This has lead to bugs wherein the 2 arrays didn't match.
     *
     * This method combines the argType & arg as a tuple,
     * and adds strong typing to prevent bugs.
    **/
    ccall_wrapper(ident, returnType, params) {
        const argTypes = [];
        const args = [];
        for (const tuple of params) {
            argTypes.push(tuple[0]);
            args.push(tuple[1]);
        }
        return this.module.ccall(ident, returnType, argTypes, args);
    }
    /**
     * ----- General -----
    **/
    version() {
        // S4Err S4_GetVersionString(size_t	bufSize, char *outString);
        const max_bytes = 256;
        const ptr = this.module._malloc(max_bytes);
        this.err_code = this.ccall_wrapper("S4_GetVersionString", "number", [
            ["number", max_bytes],
            ["number", ptr]
        ]);
        let result = "";
        if (this.err_code == S4Err.NoErr) {
            result = this.module.UTF8ToString(ptr);
        }
        this.module._free(ptr);
        return result;
    }
    /**
     * Converts the given `err_code` to a human-readable string.
     * If no `err_code` is passed, uses this.err_code automatically.
    **/
    err_str(in_err_code) {
        // S4Err S4_GetErrorString(S4Err err, size_t bufSize, char *outString);
        const max_bytes = 256;
        const ptr = this.module._malloc(max_bytes);
        const input = (in_err_code == null) ? this.err_code : in_err_code;
        this.err_code = this.ccall_wrapper("S4_GetErrorString", "number", [
            ["number", input],
            ["number", max_bytes],
            ["number", ptr]
        ]);
        let result = "";
        if (this.err_code == S4Err.NoErr) {
            result = this.module.UTF8ToString(ptr);
        }
        this.module._free(ptr);
        return result;
    }
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
    hash_do(algorithm, data) {
        // S4Err HASH_DO(HASH_Algorithm algorithm,
        //               const void*    in,
        //               size_t         inlen,
        //               size_t         outLen,
        //               void*          out);
        const num_bytes = Math.ceil(this.hash_getSizeInBits(algorithm) / 8);
        if (num_bytes == 0) {
            return null;
        }
        const ptr = this.module._malloc(num_bytes);
        this.err_code = this.ccall_wrapper("HASH_DO", "number", [
            ["number", algorithm],
            ["array", data],
            ["number", data.byteLength],
            ["number", num_bytes],
            ["number", ptr]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr, num_bytes);
        }
        this.module._free(ptr);
        return result;
    }
    hash_getSizeInBits(algorithm) {
        // S4Err HASH_GetBits(HASH_Algorithm algorithm, size_t *hashBits);
        const ptr = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("HASH_GetBits", "number", [
            ["number", algorithm],
            ["number", ptr]
        ]);
        let result = 0;
        if (this.err_code == S4Err.NoErr) {
            result = this.module.getValue(ptr, "i32");
        }
        this.module._free(ptr);
        return result;
    }
    hash_algorithmIsAvailable(algorithm) {
        // bool HASH_AlgorithmIsAvailable(HASH_Algorithm algorithm);
        const result = this.ccall_wrapper("HASH_AlgorithmIsAvailable", "number", [
            ["number", algorithm]
        ]);
        return result;
    }
    hash_init(algorithm) {
        // S4Err HASH_Init(HASH_Algorithm   algorithm,
        //                 HASH_ContextRef* ctx);
        const ptr = this.module._malloc(NUM_BYTES_POINTER);
        this.err_code = this.ccall_wrapper("HASH_Init", "number", [
            ["number", algorithm],
            ["number", ptr]
        ]);
        let context = null;
        if (this.err_code == S4Err.NoErr) {
            context = this.module.getValue(ptr, "*");
        }
        this.module._free(ptr);
        return context;
    }
    hash_getSize(context) {
        // S4Err HASH_GetSize(HASH_ContextRef  ctx, size_t *hashSize);
        const ptr = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("HASH_GetSize", "number", [
            ["number", context],
            ["number", ptr]
        ]);
        let result = 0;
        if (this.err_code == S4Err.NoErr) {
            result = this.module.getValue(ptr, "i32");
        }
        this.module._free(ptr);
        return result;
    }
    hash_update(context, data) {
        // S4Err HASH_Update(HASH_ContextRef ctx, const void *data, size_t dataLength);
        this.err_code = this.ccall_wrapper("HASH_Update", "number", [
            ["number", context],
            ["array", data],
            ["number", data.byteLength]
        ]);
        return this.err_code;
    }
    hash_final(context) {
        // S4Err HASH_Final(HASH_ContextRef ctx,
        //                  void*           hashOut);
        const num_bytes = this.hash_getSize(context);
        if (num_bytes == 0) {
            return null;
        }
        const ptr = this.module._malloc(num_bytes);
        this.err_code = this.ccall_wrapper("HASH_Final", "number", [
            ["number", context],
            ["number", ptr]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr, num_bytes);
        }
        this.module._free(ptr);
        return result;
    }
    hash_reset(context) {
        // S4Err HASH_Reset(HASH_ContextRef  ctx);
        this.err_code = this.ccall_wrapper("HASH_Reset", "number", [
            ["number", context]
        ]);
        return this.err_code;
    }
    hash_free(context) {
        // void HASH_Free(HASH_ContextRef  ctx);
        this.ccall_wrapper("HASH_Free", null, [
            ["number", context]
        ]);
    }
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
    cipher_getKeySizeInBits(algorithm) {
        // S4Err Cipher_GetKeySize(Cipher_Algorithm algorithm, size_t *keyBits);
        const ptr = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("Cipher_GetKeySize", "number", [
            ["number", algorithm],
            ["number", ptr]
        ]);
        let result = 0;
        if (this.err_code == S4Err.NoErr) {
            result = this.module.getValue(ptr, "i32");
        }
        this.module._free(ptr);
        return result;
    }
    /**
     * Returns the size of the block the cipher operates on (in bytes).
    **/
    cipher_getBlockSize(algorithm) {
        // S4Err Cipher_GetBlockSize(Cipher_Algorithm algorithm, size_t *blockSize);
        const ptr = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("Cipher_GetBlockSize", "number", [
            ["number", algorithm],
            ["number", ptr]
        ]);
        let result = 0;
        if (this.err_code == S4Err.NoErr) {
            result = this.module.getValue(ptr, "i32");
        }
        this.module._free(ptr);
        return result;
    }
    cipher_algorithmIsAvailable(algorithm) {
        // bool Cipher_AlgorithmIsAvailable(Cipher_Algorithm algorithm);
        const result = this.ccall_wrapper("Cipher_AlgorithmIsAvailable", "number", [
            ["number", algorithm]
        ]);
        return result;
    }
    /**
     * ----- Cipher Mode: Electronic Codebook (ECB) -----
     *
     * Note:
     *   ECB mode is fine for encrypting a single block,
     *   but not well-designed for encrypting multiple blocks:
     *
     *   https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)
    **/
    ecb_encrypt(options) {
        // S4Err ECB_Encrypt(Cipher_Algorithm algorithm,
        //                   const void*	     key,
        //                   const void*      in,
        //                   size_t           bytesIn,
        //                   void*            out);
        const { algorithm, key, input } = options;
        const data_size = this.cipher_getBlockSize(algorithm);
        if (data_size == null) {
            return null;
        }
        const ptr_data = this.module._malloc(data_size);
        this.err_code = this.ccall_wrapper("ECB_Encrypt", "number", [
            ["number", algorithm],
            ["array", key],
            ["array", input],
            ["number", input.byteLength],
            ["number", ptr_data]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr_data, data_size);
        }
        this.module._free(ptr_data);
        return result;
    }
    ecb_decrypt(options) {
        // S4Err ECB_Decrypt(Cipher_Algorithm algorithm,
        //                   const void*      key,
        //                   const void*      in,
        //                   size_t           bytesIn,
        //                   void*            out);
        const { algorithm, key, input } = options;
        const data_size = this.cipher_getBlockSize(algorithm);
        if (data_size == null) {
            return null;
        }
        const ptr_data = this.module._malloc(data_size);
        this.err_code = this.ccall_wrapper("ECB_Decrypt", "number", [
            ["number", algorithm],
            ["array", key],
            ["array", input],
            ["number", input.byteLength],
            ["number", ptr_data]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr_data, data_size);
        }
        this.module._free(ptr_data);
        return result;
    }
    /**
     * ----- Cipher Mode: Cipher Block Chaining (CBC) -----
    **/
    cbc_init(options) {
        // S4Err CBC_Init(Cipher_Algorithm cipher,
        //                const void*      key,
        //                const void*      iv,
        //                CBC_ContextRef* ctxOut);
        const { algorithm, key, iv } = options;
        const ptr = this.module._malloc(NUM_BYTES_POINTER);
        this.err_code = this.ccall_wrapper("CBC_Init", "number", [
            ["number", algorithm],
            ["array", key],
            ["array", iv],
            ["number", ptr]
        ]);
        let context = null;
        if (this.err_code == S4Err.NoErr) {
            context = this.module.getValue(ptr, "*");
        }
        this.module._free(ptr);
        return context;
    }
    cbc_getAlgorithm(context) {
        // S4Err CBC_GetAlgorithm(CBC_ContextRef    ctx,
        //                        Cipher_Algorithm* algorithm);
        const ptr = this.module._malloc(NUM_BYTES_POINTER);
        this.err_code = this.ccall_wrapper("CBC_GetAlgorithm", "number", [
            ["number", context],
            ["number", ptr]
        ]);
        let algorithm = null;
        if (this.err_code == S4Err.NoErr) {
            algorithm = this.module.getValue(ptr, "*");
        }
        this.module._free(ptr);
        if (algorithm) {
            if (typeof S4CipherAlgorithm[algorithm] === 'undefined') {
                return null;
            }
            else {
                return algorithm;
            }
        }
        else {
            return null;
        }
    }
    cbc_encrypt(context, input) {
        // S4Err CBC_Encrypt(CBC_ContextRef ctx,
        //                   const void*	   in,
        //                   size_t         bytesIn,
        //                   void*          out);
        const algorithm = this.cbc_getAlgorithm(context);
        if (algorithm == null) {
            return null;
        }
        const data_size = this.cipher_getBlockSize(algorithm);
        if (data_size == null) {
            return null;
        }
        const ptr_data = this.module._malloc(data_size);
        this.err_code = this.ccall_wrapper("CBC_Encrypt", "number", [
            ["number", context],
            ["array", input],
            ["number", input.byteLength],
            ["number", ptr_data]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr_data, data_size);
        }
        this.module._free(ptr_data);
        return result;
    }
    cbc_decrypt(context, input) {
        // S4Err CBC_Decrypt(CBC_ContextRef ctx,
        //                   const void*    in,
        //                   size_t         bytesIn,
        //                   void*          out);
        const algorithm = this.cbc_getAlgorithm(context);
        if (algorithm == null) {
            return null;
        }
        const data_size = this.cipher_getBlockSize(algorithm);
        if (data_size == null) {
            return null;
        }
        const ptr_data = this.module._malloc(data_size);
        this.err_code = this.ccall_wrapper("CBC_Decrypt", "number", [
            ["number", context],
            ["array", input],
            ["number", input.byteLength],
            ["number", ptr_data]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr_data, data_size);
        }
        this.module._free(ptr_data);
        return result;
    }
    cbc_free(context) {
        // void CBC_Free(CBC_ContextRef  ctx);
        this.ccall_wrapper("CBC_Free", null, [
            ["number", context],
        ]);
    }
    cbc_encryptPad(options) {
        // S4Err CBC_EncryptPAD(Cipher_Algorithm algorithm,
        //                      uint8_t*         key,
        //                      const uint8_t*   iv,
        //                      const uint8_t*   in,
        //                      size_t           in_len,
        //                      uint8_t**        outData,
        //                      size_t*          outSize);
        const { algorithm, key, iv, input } = options;
        const ptr_ptr_data = this.module._malloc(NUM_BYTES_POINTER);
        const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("CBC_EncryptPAD", "number", [
            ["number", algorithm],
            ["array", key],
            ["array", iv],
            ["array", input],
            ["number", input.byteLength],
            ["number", ptr_ptr_data],
            ["number", ptr_size],
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            const ptr_data = this.module.getValue(ptr_ptr_data, "*");
            const size = this.module.getValue(ptr_size, "i32");
            result = this.heap_copyBuffer(ptr_data, size);
            this.module._free(ptr_data);
        }
        this.module._free(ptr_ptr_data);
        this.module._free(ptr_size);
        return result;
    }
    cbc_decryptPad(options) {
        // S4Err CBC_DecryptPAD(Cipher_Algorithm algorithm,
        //                      uint8_t*         key,
        //                      const uint8_t*   iv,
        //                      const uint8_t*   in,
        //                      size_t           in_len,
        //                      uint8_t**        outData,
        //                      size_t*          outSize)
        const { algorithm, key, iv, input } = options;
        const ptr_ptr_data = this.module._malloc(NUM_BYTES_POINTER);
        const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("CBC_DecryptPAD", "number", [
            ["number", algorithm],
            ["array", key],
            ["array", iv],
            ["array", input],
            ["number", input.byteLength],
            ["number", ptr_ptr_data],
            ["number", ptr_size]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            const ptr_data = this.module.getValue(ptr_ptr_data, "*");
            const size = this.module.getValue(ptr_size, "i32");
            result = this.heap_copyBuffer(ptr_data, size);
            this.module._free(ptr_data);
        }
        this.module._free(ptr_ptr_data);
        this.module._free(ptr_size);
        return result;
    }
    /**
     * ----- Tweakable Block Cipher -----
    **/
    /**
     * Initializes a Tweakable Block Cipher context.
     *
     * The key.byteLength should be appropriate for the given algorithm.
     * You can use cipher_getSize(algorithm) to determine the length dynamically.
    **/
    tbc_init(algorithm, key) {
        // S4Err TBC_Init(Cipher_Algorithm algorithm,
        //                const void*      key,
        //                TBC_ContextRef*  ctx);
        // TODO: TBC_Init should take keyLenght parameter.
        const ptr = this.module._malloc(NUM_BYTES_POINTER);
        this.err_code = this.ccall_wrapper("TBC_Init", "number", [
            ["number", algorithm],
            ["array", key],
            ["number", ptr]
        ]);
        let context = null;
        if (this.err_code == S4Err.NoErr) {
            context = this.module.getValue(ptr, "*");
        }
        this.module._free(ptr);
        return context;
    }
    tbc_setTweek(context, tweek) {
        // S4Err TBC_SetTweek(TBC_ContextRef ctx,
        //                    const void*    tweek);
        this.err_code = this.ccall_wrapper("TBC_SetTweek", "number", [
            ["number", context],
            ["array", tweek],
        ]);
        return this.err_code;
    }
    tbc_encrypt(context, data) {
        // S4Err TBC_Encrypt(TBC_ContextRef ctx,
        //                   const void*    in,
        //                   void*          out);
        const data_size = data.byteLength;
        // TODO: Can I verify the data_size is correct ???
        // This looks like it would be an easy mistake to make...
        const ptr = this.module._malloc(data_size);
        this.err_code = this.ccall_wrapper("TBC_Encrypt", "number", [
            ["number", context],
            ["array", data],
            ["number", ptr]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr, data_size);
        }
        this.module._free(ptr);
        return result;
    }
    tbc_decrypt(context, data) {
        // S4Err TBC_Decrypt(TBC_ContextRef ctx,
        //                   const void*    in,
        //                   void*          out);
        const data_size = data.byteLength;
        // TODO: Can I verify the data_size is correct ???
        // This looks like it would be an easy mistake to make...
        const ptr = this.module._malloc(data_size);
        this.err_code = this.ccall_wrapper("TBC_Decrypt", "number", [
            ["number", context],
            ["array", data],
            ["number", ptr]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            result = this.heap_copyBuffer(ptr, data_size);
        }
        this.module._free(ptr);
        return result;
    }
    tbc_free(context) {
        // void TBC_Free(TBC_ContextRef  ctx);
        this.ccall_wrapper("TBC_Free", null, [
            ["number", context],
        ]);
    }
    /**
     * ----- Elliptic-curve cryptography -----
    **/
    ecc_init() {
        // S4Err ECC_Init(ECC_ContextRef* ctx);
        const ptr = this.module._malloc(NUM_BYTES_POINTER);
        this.err_code = this.ccall_wrapper("ECC_Init", "number", [
            ["number", ptr],
        ]);
        let context = null;
        if (this.err_code == S4Err.NoErr) {
            context = this.module.getValue(ptr, "*");
        }
        this.module._free(ptr);
        return context;
    }
    ecc_generate(context, keySize) {
        // S4Err ECC_Generate(ECC_ContextRef ctx,
        //                    size_t         keysize);
        this.err_code = this.ccall_wrapper("ECC_Generate", "number", [
            ["number", context],
            ["number", keySize]
        ]);
        return this.err_code;
    }
    ecc_import(context, data) {
        // S4Err ECC_Import(ECC_ContextRef ctx,
        //                  void*          in,
        //                  size_t         inlen);
        this.err_code = this.ccall_wrapper("ECC_Import", "number", [
            ["number", context],
            ["array", data],
            ["number", data.byteLength],
        ]);
        return this.err_code;
    }
    ecc_export(context, includePrivateKey) {
        // S4Err ECC_Export(ECC_ContextRef ctx,
        //                  int            exportPrivate,
        //                  void*          outData,
        //                  size_t         bufSize,
        //                  size_t*        datSize);
        const buffer_malloc_size = 1024;
        const ptr_buffer = this.module._malloc(buffer_malloc_size);
        const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("ECC_Export", "number", [
            ["number", context],
            ["boolean", includePrivateKey],
            ["number", ptr_buffer],
            ["number", buffer_malloc_size],
            ["number", ptr_size],
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            const buffer_fill_size = this.module.getValue(ptr_size, "i32");
            result = this.heap_copyBuffer(ptr_buffer, buffer_fill_size);
        }
        this.module._free(ptr_size);
        this.module._free(ptr_buffer);
        return result;
    }
    /**
     * Returns whether or not the ECC key is a private key.
     * Generally this method is used when importing key material,
     * and you want to find ensure the imported key material is a private key,
     * as opposed to just a public key.
    **/
    ecc_isPrivate(context) {
        // bool ECC_isPrivate(ECC_ContextRef ctx);
        const result = this.ccall_wrapper("ECC_isPrivate", "number", [
            ["number", context],
        ]);
        return result;
    }
    ecc_free(context) {
        // void ECC_Free(ECC_ContextRef ctx);
        this.ccall_wrapper("ECC_Free", null, [
            ["number", context],
        ]);
    }
    /**
     * ----- Key Wrappers -----
    **/
    key_deserializeKey(key) {
        // S4Err S4Key_DeserializeKey(uint8_t*         inData,
        //                            size_t           inLen,
        //                            S4KeyContextRef* ctxOut);
        const ptr = this.module._malloc(NUM_BYTES_POINTER);
        this.err_code = this.ccall_wrapper("S4Key_DeserializeKey", "number", [
            ["array", key],
            ["number", key.byteLength],
            ["number", ptr]
        ]);
        let context = null;
        if (this.err_code == S4Err.NoErr) {
            context = this.module.getValue(ptr, "*");
        }
        this.module._free(ptr);
        return context;
    }
    key_newTBC(algorithm, key) {
        // S4Err S4Key_NewTBC(Cipher_Algorithm algorithm,
        //                    const void*      key,
        //                    S4KeyContextRef* ctx);
        const ptr = this.module._malloc(NUM_BYTES_POINTER);
        this.err_code = this.ccall_wrapper("S4Key_NewTBC", "number", [
            ["number", algorithm],
            ["array", key],
            ["number", ptr]
        ]);
        let context = null;
        if (this.err_code == S4Err.NoErr) {
            context = this.module.getValue(ptr, "*");
        }
        this.module._free(ptr);
        return context;
    }
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
    key_wrapToKey(context_outer, context_inner) {
        // S4Err S4Key_SerializeToS4Key(S4KeyContextRef ctx,
        //                              S4KeyContextRef passKeyCtx,
        //                              uint8_t**       outData,
        //                              size_t*         outSize);
        const ptr_ptr_data = this.module._malloc(NUM_BYTES_POINTER);
        const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("S4Key_SerializeToS4Key", "number", [
            ["number", context_inner],
            ["number", context_outer],
            ["number", ptr_ptr_data],
            ["number", ptr_size],
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            const ptr_data = this.module.getValue(ptr_ptr_data, "*");
            const size = this.module.getValue(ptr_size, "i32");
            result = this.heap_copyBuffer(ptr_data, size);
            this.module._free(ptr_data);
        }
        this.module._free(ptr_ptr_data);
        this.module._free(ptr_size);
        return result;
    }
    key_getProperty(context, property) {
        // S4Err S4Key_GetProperty(S4KeyContextRef    ctx,
        //                         const char*        propName,
        //                         S4KeyPropertyType* outPropType,
        //                         void*              outData,
        //                         size_t             bufSize,
        //                         size_t*            datSize);
        const ptr_type = this.module._malloc(NUM_BYTES_POINTER);
        const buffer_malloc_size = 1024;
        const ptr_data = this.module._malloc(buffer_malloc_size);
        const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);
        this.err_code = this.ccall_wrapper("S4Key_GetProperty", "number", [
            ["number", context],
            ["string", property],
            ["number", ptr_type],
            ["number", ptr_data],
            ["number", buffer_malloc_size],
            ["number", ptr_size]
        ]);
        let result = null;
        if (this.err_code == S4Err.NoErr) {
            const type = this.module.getValue(ptr_type, "i32");
            switch (type) {
                case S4PropertyType.UTF8String: {
                    result = this.module.UTF8ToString(ptr_data);
                    break;
                }
                case S4PropertyType.Binary: {
                    const size = this.module.getValue(ptr_size, "i32");
                    result = this.heap_copyBuffer(ptr_data, size);
                    break;
                }
                case S4PropertyType.Numeric: {
                    // What type of number ?
                    // Not enough information...
                    break;
                }
                case S4PropertyType.Time: {
                    // Don't know what this means.
                    // Code isn't properly documented.
                    break;
                }
            }
        }
        else {
            console.log("S4Key_GetProperty(): this.err_code: " + this.err_code);
        }
        this.module._free(ptr_type);
        this.module._free(ptr_data);
        this.module._free(ptr_size);
        return result;
    }
    key_free(context) {
        // void S4Key_Free(S4KeyContextRef ctx);
        this.ccall_wrapper("S4Key_Free", null, [
            ["number", context]
        ]);
    }
    /**
     * ----- Internal Utilities -----
    **/
    heap_copyBuffer(ptr, num_bytes) {
        // From the docs:
        // 
        // > new TypedArray(buffer [, byteOffset [, length]]);
        // > When called with a buffer, and optionally a byteOffset and a length argument,
        // > a new typed array view is created that views the specified ArrayBuffer [...]
        // 
        // In other words, the BYTES ARE NOT COPIED.
        // This is unsafe.
        // We need to get our own copy, so the WebAssembly stuff can modify it's memory safely.
        // 
        // > new TypedArray(typedArray);
        // > When called with a typedArray argument, which can be an object of any of the
        // > typed array types (such as Int32Array), the typedArray gets copied into a
        // > new typed array.
        // 
        const unsafe_not_copied = new Uint8Array(this.module.HEAPU8.buffer, ptr, num_bytes);
        const result = new Uint8Array(unsafe_not_copied);
        return result;
    }
    /**
     * ----- Javascript Utilities -----
    **/
    util_concatBuffers(buffers) {
        const totalByteLength = buffers.reduce((total, buffer) => {
            return (total + buffer.byteLength);
        }, 0);
        const result = new Uint8Array(totalByteLength);
        let offset = 0;
        for (const buffer of buffers) {
            result.set(buffer, offset);
            offset += buffer.length;
        }
        return result;
    }
    util_compareBuffers(bufferA, bufferB) {
        if (bufferA == bufferB) {
            return true;
        }
        if (bufferA.byteLength != bufferB.byteLength) {
            return false;
        }
        for (let i = 0; i < bufferA.byteLength; i++) {
            if (bufferA[i] != bufferB[i]) {
                return false;
            }
        }
        return true;
    }
    util_hexString(buffer) {
        return Array.prototype.map.call(buffer, (x) => ('00' + x.toString(16)).slice(-2)).join('');
    }
}
exports.S4 = S4;
