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

export type EmscriptenJavascriptType = "number"|"string"|"array"|"boolean"|null;

export type LlvmIrType = "i8"|"i16"|"i32"|"i64"|"float"|"double"|"*";

export interface EmscriptenModule {
	HEAPU8: Uint8Array,
	
	_malloc: (numBytes: number)=> number,
	_free: (ptr: number)=> void,

	ccall : (
		ident      : string,
		returnType : EmscriptenJavascriptType,
		argTypes   : EmscriptenJavascriptType[],
		args       : any[]
	) => any,

	setValue: (
		ptr   : number,
		value : any,
		type  : LlvmIrType
	)=> void,

	getValue : (
		ptr  : number,
		type : LlvmIrType
	)=> number,

	UTF8ToString: (ptr: number)=> string,
}

export interface S4Module extends EmscriptenModule {
	_S4_Init: ()=> S4Err
}

export enum S4Err
{
	NoErr                  =  0,
	NOP                    =  1,
	UnknownError           =  2,
	BadParams              =  3,
	OutOfMemory            =  4,
	BufferTooSmall         =  5,
	UserAbort              =  6,
	UnknownRequest         =  7,
	LazyProgrammer         =  8,
	AssertFailed           =  9,
	FeatureNotAvailable    = 10,
	ResourceUnavailable    = 11,
	NotConnected           = 12,
	ImproperInitialization = 13,
	CorruptData            = 14,
	SelfTestFailed         = 15,
	BadIntegrity           = 16,
	BadHashNumber          = 17,
	BadCipherNumber        = 18,
	BadPRNGNumber          = 19,
	SecretsMismatch        = 20,
	KeyNotFound            = 21,
	ProtocolError          = 22,
	ProtocolContention     = 23,
	KeyLocked              = 24,
	KeyExpired             = 25,
	EndOfIteration         = 26,
	OtherError             = 27,
	PubPrivKeyNotFound     = 28,
	NotEnoughShares        = 29,
	PropertyNotFound       = 30
};

export enum S4HashAlgorithm {
   MD5        = 1,
   SHA1       = 2,
   SHA224     = 3,
   SHA256     = 4,
   SHA384     = 5,
   SHA512     = 6,
   SKEIN256   = 7,
   SKEIN512   = 8,
   SKEIN1024  = 9,
	SHA512_256 = 10,
	
	xxHash32   = 20,
	xxHash64   = 21,
	
	SHA3_224   = 30,
	SHA3_256   = 31,
	SHA3_384   = 32,
	SHA3_512   = 33,
};

export enum S4CipherAlgorithm
{
	AES128        = 1,
	AES192        = 2,
	AES256        = 3,
	"2FISH256"    = 4,
	TWOFISH256    = 4,

	"3FISH256"    = 100,
	THREEFISH256  = 100,
	"3FISH512"    = 102,
	THREEFISH512  = 102,
	"3FISH1024"   = 103,
	THREEFISH1024 = 103,

	SharedKey     = 200,

	ECCNISTP384   = 300,
	ECC41417      = 301,
};

export enum S4ECCAlgorithm
{
	NISTP384    = S4CipherAlgorithm.ECCNISTP384,
	Curve41417  = S4CipherAlgorithm.ECC41417
};

export enum S4Property {
	KeyType            = "keyType",
	KeySuite           = "keySuite",
	HashAlgorithm      = "hashAlgorithm",
	KeyData            = "keyData",
	KeyID              = "keyID",
	KeyIDString        = "keyID-String",
	Mac                = "mac",
	StartDate          = "start-date",
	ExpireDate         = "expire-date",
	EncryptedKey       = "encrypted",
	Encoding           = "encoding",
	Signature          = "signature",
	SignedBy           = "issuer",
	SignedProperties   = "signed-properties",
	SignableProperties = "signable-properties",
	SignedDate         = "issue-date",
	SigExpire          = "sig-expire",
	SigID              = "sigID"
}

enum S4PropertyType
{
	Invalid       = 0,
	UTF8String    = 1,
	Binary        = 2,
	Time          = 3,
	Numeric       = 4,
};

type EmscriptenTuple =
	["number",  number]                          |
	["string",  string]                          |
	["array",   Uint8Array|Readonly<Uint8Array>] |
	["boolean", boolean];

const NUM_BYTES_POINTER = (32 / 8);
const NUM_BYTES_SIZE_T = (32 / 8);


export class S4 {

	public static load(module: any): S4|null
	{
		if (module && module._S4_Init) {
			return new S4(module as S4Module);
		}
		
		return null;
	}

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
	public err_code: S4Err;

	private module: S4Module;
	private constructor(module: S4Module)
	{
		this.module = module;

		// As of now, the S4_Init() method will never return an error,
		// despite the fact that the API indicates it could.
		//  (Reserved for potential future changes.)
		// 
		this.err_code = this.module._S4_Init();
		if (this.err_code != S4Err.NoErr) {
			console.log("S4_Init(): err: "+ this.err_code)
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
	private ccall_wrapper(
		ident      : string,
		returnType : EmscriptenJavascriptType,
		params     : EmscriptenTuple[]
	): any
	{
		const argTypes: EmscriptenJavascriptType[] = [];
		const args: any[] = [];

		for (const tuple of params) {
			argTypes.push(tuple[0]);
			args.push(tuple[1]);
		}

		return this.module.ccall(ident, returnType, argTypes, args);
	}

	/**
	 * ----- General -----
	**/

	public version(): string
	{
		// S4Err S4_GetVersionString(size_t	bufSize, char *outString);

		const max_bytes = 256;
		const ptr = this.module._malloc(max_bytes);
		
		this.err_code = this.ccall_wrapper(
			"S4_GetVersionString", "number", [
				["number", max_bytes],
				["number", ptr]
			]
		);

		let result = "";
		if (this.err_code == S4Err.NoErr)
		{
			result = this.module.UTF8ToString(ptr);
		}

		this.module._free(ptr);
		return result;
	}

	/**
	 * Converts the given `err_code` to a human-readable string.
	 * If no `err_code` is passed, uses this.err_code automatically.
	**/
	public err_str(in_err_code ?: number): string
	{
		// S4Err S4_GetErrorString(S4Err err, size_t bufSize, char *outString);

		const max_bytes = 256;
		const ptr = this.module._malloc(max_bytes);

		const input = (in_err_code == null) ? this.err_code : in_err_code;

		this.err_code = this.ccall_wrapper(
			"S4_GetErrorString", "number", [
				["number", input],
				["number", max_bytes],
				["number", ptr]
			]
		);

		let result = "";
		if (this.err_code == S4Err.NoErr)
		{
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
	public hash_do(
		algorithm : S4HashAlgorithm,
		data      : Readonly<Uint8Array>
	): Uint8Array|null
	{
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

		this.err_code = this.ccall_wrapper(
			"HASH_DO", "number", [
				["number", algorithm],
				["array",  data],
				["number", data.byteLength],
				["number", num_bytes],
				["number", ptr]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr, num_bytes);
		}

		this.module._free(ptr);
		return result;
	}

	public hash_getSizeInBits(algorithm: S4HashAlgorithm): number
	{
		// S4Err HASH_GetBits(HASH_Algorithm algorithm, size_t *hashBits);

		const ptr = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"HASH_GetBits", "number", [
				["number", algorithm],
				["number", ptr]
			]
		);

		let result = 0;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.module.getValue(ptr, "i32");
		}

		this.module._free(ptr);
		return result;
	}

	public hash_algorithmIsAvailable(algorithm: S4HashAlgorithm): boolean
	{
		// bool HASH_AlgorithmIsAvailable(HASH_Algorithm algorithm);

		const result = this.ccall_wrapper(
			"HASH_AlgorithmIsAvailable", "number", [
				["number", algorithm]
			]
		);

		return result;
	}

	public hash_init(algorithm: S4HashAlgorithm): number|null
	{
		// S4Err HASH_Init(HASH_Algorithm   algorithm,
		//                 HASH_ContextRef* ctx);

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"HASH_Init", "number", [
				["number", algorithm],
				["number", ptr]
			]
		);

		let context: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			context = this.module.getValue(ptr, "*");
		}

		this.module._free(ptr);
		return context;
	}

	public hash_getSize(context: number): number
	{
		// S4Err HASH_GetSize(HASH_ContextRef  ctx, size_t *hashSize);

		const ptr = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"HASH_GetSize", "number", [
				["number", context],
				["number", ptr]
			]
		);

		let result = 0;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.module.getValue(ptr, "i32");
		}

		this.module._free(ptr);
		return result;
	}

	public hash_update(
		context : number,
		data    : Readonly<Uint8Array>
	): S4Err
	{
		// S4Err HASH_Update(HASH_ContextRef ctx, const void *data, size_t dataLength);

		this.err_code = this.ccall_wrapper(
			"HASH_Update", "number", [
				["number", context],
				["array",  data],
				["number", data.byteLength]
			]
		);
		
		return this.err_code;
	}

	public hash_final(context: number): Uint8Array|null
	{
		// S4Err HASH_Final(HASH_ContextRef ctx,
		//                  void*           hashOut);

		const num_bytes = this.hash_getSize(context);
		if (num_bytes == 0) {
			return null;
		}

		const ptr = this.module._malloc(num_bytes);

		this.err_code = this.ccall_wrapper(
			"HASH_Final", "number", [
				["number", context],
				["number", ptr]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr, num_bytes);
		}

		this.module._free(ptr);
		return result;
	}

	public hash_reset(context: number): S4Err
	{
		// S4Err HASH_Reset(HASH_ContextRef  ctx);

		this.err_code = this.ccall_wrapper(
			"HASH_Reset", "number", [
				["number", context]
			]
		);

		return this.err_code;
	}

	public hash_free(context: number): void
	{
		// void HASH_Free(HASH_ContextRef  ctx);

		this.ccall_wrapper(
			"HASH_Free", null, [
				["number", context]
			]
		);
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
	public cipher_getKeySizeInBits(algorithm: S4CipherAlgorithm): number
	{
		// S4Err Cipher_GetKeySize(Cipher_Algorithm algorithm, size_t *keyBits);

		const ptr = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"Cipher_GetKeySize", "number", [
				["number", algorithm],
				["number", ptr]
			]
		);

		let result = 0;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.module.getValue(ptr, "i32");			
		}

		this.module._free(ptr);
		return result;
	}

	/**
	 * Returns the size of the block the cipher operates on (in bytes).
	**/
	public cipher_getBlockSize(algorithm: S4CipherAlgorithm): number
	{
		// S4Err Cipher_GetBlockSize(Cipher_Algorithm algorithm, size_t *blockSize);

		const ptr = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"Cipher_GetBlockSize", "number", [
				["number", algorithm],
				["number", ptr]
			]
		);

		let result = 0;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.module.getValue(ptr, "i32");			
		}

		this.module._free(ptr);
		return result;
	}

	public cipher_algorithmIsAvailable(algorithm: S4CipherAlgorithm): boolean
	{
		// bool Cipher_AlgorithmIsAvailable(Cipher_Algorithm algorithm);

		const result = this.ccall_wrapper(
			"Cipher_AlgorithmIsAvailable", "number", [
				["number", algorithm]
			]
		);

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

	public ecb_encrypt(
		options: {
			algorithm : S4CipherAlgorithm
			key       : Readonly<Uint8Array>,
			input     : Readonly<Uint8Array>
		}
	): Uint8Array|null
	{
		// S4Err ECB_Encrypt(Cipher_Algorithm algorithm,
		//                   const void*	     key,
		//                   const void*      in,
		//                   size_t           bytesIn,
		//                   void*            out);
		// 
		// Notes:
		// - ECB_Encrypt will encrypt multiple blocks.
		//   For example, if the block size is 16 bytes (128 bits),
		//   you can pass in 32 bytes, and it will encrypt 2 blocks.
		// 
		// - The input must be a multiple of the blockSize,
		//   or S4 will return an error.

		const {algorithm, key, input} = options;

		const data_size = input.byteLength;
		const ptr_data = this.module._malloc(data_size);

		this.err_code = this.ccall_wrapper(
			"ECB_Encrypt", "number", [
				["number", algorithm],
				["array", key],
				["array", input],
				["number", input.byteLength],
				["number", ptr_data]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr_data, data_size);
		}

		this.module._free(ptr_data);
		return result;
	}

	public ecb_decrypt(
		options: {
			algorithm : S4CipherAlgorithm
			key       : Readonly<Uint8Array>,
			input     : Readonly<Uint8Array>
		}
	):  Uint8Array|null
	{
		// S4Err ECB_Decrypt(Cipher_Algorithm algorithm,
		//                   const void*      key,
		//                   const void*      in,
		//                   size_t           bytesIn,
		//                   void*            out);
		// 
		// Notes:
		// - ECB_Decrypt will decrypt multiple blocks.
		//   For example, if the block size is 16 bytes (128 bits),
		//   you can pass in 32 bytes, and it will decrypt 2 blocks.
		// 
		// - The input must be a multiple of the blockSize,
		//   or S4 will return an error.

		const {algorithm, key, input} = options;

		const data_size = input.byteLength;
		const ptr_data = this.module._malloc(data_size);

		this.err_code = this.ccall_wrapper(
			"ECB_Decrypt", "number", [
				["number", algorithm],
				["array", key],
				["array", input],
				["number", input.byteLength],
				["number", ptr_data]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr_data, data_size);
		}

		this.module._free(ptr_data);
		return result;
	}

	/**
	 * ----- Cipher Mode: Cipher Block Chaining (CBC) -----
	**/

	public cbc_init(
		options: {
			algorithm : S4CipherAlgorithm
			key       : Readonly<Uint8Array>,
			iv        : Readonly<Uint8Array>
		}
	): number|null
	{
		// S4Err CBC_Init(Cipher_Algorithm cipher,
		//                const void*      key,
		//                const void*      iv,
		//                CBC_ContextRef* ctxOut);

		const {algorithm, key, iv} = options;

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"CBC_Init", "number", [
				["number", algorithm],
				["array",  key],
				["array",  iv],
				["number", ptr]
			]
		);

		let context: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			context = this.module.getValue(ptr, "*");
		}

		this.module._free(ptr);
		return context;
	}

	public cbc_getAlgorithm(context: number): S4CipherAlgorithm|null
	{
		// S4Err CBC_GetAlgorithm(CBC_ContextRef    ctx,
		//                        Cipher_Algorithm* algorithm);

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"CBC_GetAlgorithm", "number", [
				["number", context],
				["number", ptr]
			]
		);

		let algorithm: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			algorithm = this.module.getValue(ptr, "*");
		}

		this.module._free(ptr);
		if (algorithm)
		{
			if (typeof S4CipherAlgorithm[algorithm] === 'undefined') {
				return null;
		  	} else {
				return <S4CipherAlgorithm>algorithm;
			}
		}
		else
		{
			return null;
		}
	}

	public cbc_encrypt(context: number, input: Readonly<Uint8Array>): Uint8Array|null
	{
		// S4Err CBC_Encrypt(CBC_ContextRef ctx,
		//                   const void*	   in,
		//                   size_t         bytesIn,
		//                   void*          out);
		// 
		// Notes:
		// - CBC_Encrypt will encrypt multiple blocks.
		//   For example, if the block size is 16 bytes (128 bits),
		//   you can pass in 32 bytes, and it will encrypt 2 blocks.
		// 
		// - The input must be a multiple of the blockSize,
		//   or S4 will return an error.

		const data_size = input.byteLength;
		const ptr_data = this.module._malloc(data_size);

		this.err_code = this.ccall_wrapper(
			"CBC_Encrypt", "number", [
				["number", context],
				["array", input],
				["number", input.byteLength],
				["number", ptr_data]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr_data, data_size);
		}

		this.module._free(ptr_data);
		return result;
	}

	public cbc_decrypt(context: number, input: Readonly<Uint8Array>): Uint8Array|null
	{
		// S4Err CBC_Decrypt(CBC_ContextRef ctx,
		//                   const void*    in,
		//                   size_t         bytesIn,
		//                   void*          out);
		// 
		// Notes:
		// - CBC_Decrypt will decrypt multiple blocks.
		//   For example, if the block size is 16 bytes (128 bits),
		//   you can pass in 32 bytes, and it will decrypt 2 blocks.
		// 
		// - The input must be a multiple of the blockSize,
		//   or S4 will return an error.

		const data_size = input.byteLength;
		const ptr_data = this.module._malloc(data_size);

		this.err_code = this.ccall_wrapper(
			"CBC_Decrypt", "number", [
				["number", context],
				["array", input],
				["number", input.byteLength],
				["number", ptr_data]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr_data, data_size);
		}

		this.module._free(ptr_data);
		return result;
	}

	public cbc_free(context: number): void
	{
		// void CBC_Free(CBC_ContextRef  ctx);

		this.ccall_wrapper(
			"CBC_Free", null, [
				["number", context],
			]
		);
	}

	public cbc_encryptPad(
		options: {
			algorithm : S4CipherAlgorithm,
			key       : Readonly<Uint8Array>,
			iv        : Readonly<Uint8Array>,
			input     : Readonly<Uint8Array>
		}
	): Uint8Array|null
	{
		// S4Err CBC_EncryptPAD(Cipher_Algorithm algorithm,
		//                      uint8_t*         key,
		//                      const uint8_t*   iv,
		//                      const uint8_t*   in,
		//                      size_t           in_len,
		//                      uint8_t**        outData,
		//                      size_t*          outSize);

		const {algorithm, key, iv, input} = options;

		const ptr_ptr_data = this.module._malloc(NUM_BYTES_POINTER);
		const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"CBC_EncryptPAD", "number", [
				["number", algorithm],
				["array",  key],
				["array",  iv],
				["array",  input],
				["number", input.byteLength],
				["number", ptr_ptr_data],
				["number", ptr_size],
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			const ptr_data = this.module.getValue(ptr_ptr_data, "*");
			const size = this.module.getValue(ptr_size, "i32");

			result = this.heap_copyBuffer(ptr_data, size);

			this.module._free(ptr_data);
		}

		this.module._free(ptr_ptr_data);
		this.module._free(ptr_size);
		return result;
	}

	public cbc_decryptPad(
		options: {
			algorithm: S4CipherAlgorithm,
			key       : Readonly<Uint8Array>,
			iv        : Readonly<Uint8Array>,
			input     : Readonly<Uint8Array>
		}
	): Uint8Array|null
	{
		// S4Err CBC_DecryptPAD(Cipher_Algorithm algorithm,
		//                      uint8_t*         key,
		//                      const uint8_t*   iv,
		//                      const uint8_t*   in,
		//                      size_t           in_len,
		//                      uint8_t**        outData,
		//                      size_t*          outSize)

		const {algorithm, key, iv, input} = options;

		const ptr_ptr_data = this.module._malloc(NUM_BYTES_POINTER);
		const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"CBC_DecryptPAD", "number", [
				["number", algorithm],
				["array",  key],
				["array",  iv],
				["array",  input],
				["number", input.byteLength],
				["number", ptr_ptr_data],
				["number", ptr_size]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
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
	public tbc_init(algorithm: S4CipherAlgorithm, key: Readonly<Uint8Array>): number|null
	{
		// S4Err TBC_Init(Cipher_Algorithm algorithm,
		//                const void*      key,
		//                TBC_ContextRef*  ctx);

		// TODO: TBC_Init should take keyLenght parameter.

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"TBC_Init", "number", [
				["number", algorithm],
				["array",  key],
				["number", ptr]
			]
		);

		let context: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			context = this.module.getValue(ptr, "*");
		}

		this.module._free(ptr);
		return context;
	}

	public tbc_setTweek(
		context : number,
		tweek   : Readonly<Uint8Array>
	): S4Err
	{
		// S4Err TBC_SetTweek(TBC_ContextRef ctx,
		//                    const void*    tweek);

		this.err_code = this.ccall_wrapper(
			"TBC_SetTweek", "number", [
				["number", context],
				["array",  tweek],
			]
		);

		return this.err_code;
	}

	public tbc_encrypt(
		context : number,
		data    : Readonly<Uint8Array>
	): Uint8Array|null
	{
		// S4Err TBC_Encrypt(TBC_ContextRef ctx,
		//                   const void*    in,
		//                   void*          out);
		
		const data_size = data.byteLength;

		// TODO: Can I verify the data_size is correct ???
		// This looks like it would be an easy mistake to make...

		const ptr = this.module._malloc(data_size);

		this.err_code = this.ccall_wrapper(
			"TBC_Encrypt", "number", [
				["number", context],
				["array",  data],
				["number", ptr]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr, data_size);
		}

		this.module._free(ptr);
		return result;
	}

	public tbc_decrypt(
		context : number,
		data    : Readonly<Uint8Array>
	): Uint8Array|null
	{
		// S4Err TBC_Decrypt(TBC_ContextRef ctx,
		//                   const void*    in,
		//                   void*          out);

		const data_size = data.byteLength;
		
		// TODO: Can I verify the data_size is correct ???
		// This looks like it would be an easy mistake to make...

		const ptr = this.module._malloc(data_size);

		this.err_code = this.ccall_wrapper(
			"TBC_Decrypt", "number", [
				["number", context],
				["array",  data],
				["number", ptr]
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			result = this.heap_copyBuffer(ptr, data_size);
		}

		this.module._free(ptr);
		return result;
	}

	public tbc_free(context: number): void
	{
		// void TBC_Free(TBC_ContextRef  ctx);

		this.ccall_wrapper(
			"TBC_Free", null, [
				["number", context],
			]
		);
	}

	/**
	 * ----- Elliptic-curve cryptography -----
	**/

	public ecc_init(algorithm: S4ECCAlgorithm): number|null
	{
		// S4Err ECC_Init(ECC_Algorithm algorithm,
		//                ECC_ContextRef __NULLABLE_REF_POINTER ctx);

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"ECC_Init", "number", [
				["number", algorithm],
				["number", ptr],
			]
		);

		let context: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			context = this.module.getValue(ptr, "*");
		}

		this.module._free(ptr);
		return context;
	}

	public ecc_import(data: Readonly<Uint8Array>): number|null
	{
		// S4Err ECC_Import(const void*    in,
		//                  size_t         inlen,
		//                  ECC_ContextRef ctxOUT);

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"ECC_Import", "number", [
				["array",  data],
				["number", data.byteLength],
				["number", ptr]
			]
		);

		let context: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			context = this.module.getValue(ptr, "*");
		}

		this.module._free(ptr);
		return context;
	}

	public ecc_export(context: number, includePrivateKey: boolean): Uint8Array|null
	{
		// S4Err ECC_Export(ECC_ContextRef  ctx,
		//                  bool            exportPrivate,
		//                  void*           outData,
		//                  size_t          bufSize,
		//                  size_t*         datSize);

		const buffer_malloc_size = 1024;
		const ptr_buffer = this.module._malloc(buffer_malloc_size);

		const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"ECC_Export", "number", [
				["number",  context],
				["boolean", includePrivateKey],
				["number",  ptr_buffer],
				["number",  buffer_malloc_size],
				["number",  ptr_size],
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			const buffer_fill_size = this.module.getValue(ptr_size, "i32");

			result = this.heap_copyBuffer(ptr_buffer, buffer_fill_size);
		}

		this.module._free(ptr_size);
		this.module._free(ptr_buffer);
		return result;
	}

	/**
	 * Returns whether or not the ECC key is a private key.
	 * 
	 * All generated keys (via `ecc_init`) are private.
	 * However, that's not the case if you use `ecc_import`.
	 * 
	 * So this method is useful when importing key material,
	 * and you want to check the type of key that was imported.
	**/
	public ecc_isPrivate(context: number): boolean
	{
		// bool ECC_isPrivate(ECC_ContextRef ctx);

		const result = this.ccall_wrapper(
			"ECC_isPrivate", "number", [
				["number", context],
			]
		);

		return result;
	}

	public ecc_encrypt(context: number, input: Readonly<Uint8Array>): Uint8Array|null
	{
		// S4Err ECC_Encrypt(ECC_ContextRef pubCtx,
		//                   const void*    inData,
		//                   size_t         inDataLen,
		//                   void*          outData,
		//                   size_t         bufSize,
		//                   size_t*        outDataLen);

		// TODO: How do I know how big outData should be ?

		return null;
	}

	public ecc_decrypt(context: number, input: Readonly<Uint8Array>): Uint8Array|null
	{
		// S4Err ECC_Decrypt(ECC_ContextRef privCtx,
		//                   const void*    inData,
		//                   size_t         inDataLen,
		//                   void*          outData,
		//                   size_t         bufSize,
		//                   size_t*        outDataLen);

		// TODO: How do I know how big outData should be ?

		return null;
	}

	public ecc_sign(context: number, input: Readonly<Uint8Array>): Uint8Array|null
	{
		// S4Err ECC_Sign(ECC_ContextRef privCtx,
		//                void*          inData,
		//                size_t         inDataLen,
		//                void*          outData,
		//                size_t         bufSize,
		//                size_t*        outDataLen);

		// TODO: How do I know how big outData should be ?

		return null;
	}

	public ecc_verify(context: number, input: Readonly<Uint8Array>): Uint8Array|null
	{
		// S4Err ECC_Verify(ECC_ContextRef pubCtx,
		//                  void*          sig,
		//                  size_t         sigLen,
		//                  void*          hash,
		//                  size_t         hashLen);

		// TODO: How do I know how big outData should be ?

		return null;
	}

	public ecc_free(context: number): void
	{
		// void ECC_Free(ECC_ContextRef ctx);

		this.ccall_wrapper(
			"ECC_Free", null, [
				["number", context],
			]
		);
	}

	/**
	 * ----- Key Wrappers -----
	**/

	public key_deserializeKey(key: Readonly<Uint8Array>): number|null
	{
		// S4Err S4Key_DeserializeKey(uint8_t*         inData,
		//                            size_t           inLen,
		//                            S4KeyContextRef* ctxOut);

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"S4Key_DeserializeKey", "number", [
				["array",  key],
				["number", key.byteLength],
				["number", ptr]
			]
		);

		let context: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			context = this.module.getValue(ptr, "*");
		}

		this.module._free(ptr);
		return context;
	}

	public key_newTBC(
		algorithm : S4CipherAlgorithm,
		key       : Readonly<Uint8Array>
	): number|null
	{
		// S4Err S4Key_NewTBC(Cipher_Algorithm algorithm,
		//                    const void*      key,
		//                    S4KeyContextRef* ctx);

		const ptr = this.module._malloc(NUM_BYTES_POINTER);

		this.err_code = this.ccall_wrapper(
			"S4Key_NewTBC", "number", [
				["number", algorithm],
				["array",  key],
				["number", ptr]
			]
		);

		let context: number|null = null;
		if (this.err_code == S4Err.NoErr)
		{
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
	public key_wrapToKey(context_outer: number, context_inner: number): Uint8Array|null
	{
		// S4Err S4Key_SerializeToS4Key(S4KeyContextRef ctx,
		//                              S4KeyContextRef passKeyCtx,
		//                              uint8_t**       outData,
		//                              size_t*         outSize);

		const ptr_ptr_data = this.module._malloc(NUM_BYTES_POINTER);
		const ptr_size = this.module._malloc(NUM_BYTES_SIZE_T);

		this.err_code = this.ccall_wrapper(
			"S4Key_SerializeToS4Key", "number", [
				["number", context_inner],
				["number", context_outer],
				["number", ptr_ptr_data],
				["number", ptr_size],
			]
		);

		let result: Uint8Array|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			const ptr_data = this.module.getValue(ptr_ptr_data, "*");
			const size = this.module.getValue(ptr_size, "i32");

			result = this.heap_copyBuffer(ptr_data, size);

			this.module._free(ptr_data);
		}

		this.module._free(ptr_ptr_data);
		this.module._free(ptr_size);
		return result;
	}

	public key_getProperty(context: number, property: S4Property): any|null
	{
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

		this.err_code = this.ccall_wrapper(
			"S4Key_GetProperty", "number", [
				["number", context],
				["string", property],
				["number", ptr_type],
				["number", ptr_data],
				["number", buffer_malloc_size],
				["number", ptr_size]
			]
		);

		let result: any|null = null;
		if (this.err_code == S4Err.NoErr)
		{
			const type = this.module.getValue(ptr_type, "i32");
			switch (type)
			{
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
		else
		{
			console.log("S4Key_GetProperty(): this.err_code: "+ this.err_code);
		}

		this.module._free(ptr_type);
		this.module._free(ptr_data);
		this.module._free(ptr_size);
		return result;
	}

	public key_free(context: number): void
	{
		// void S4Key_Free(S4KeyContextRef ctx);

		this.ccall_wrapper(
			"S4Key_Free", null, [
				["number", context]
			]
		);
	}

	/**
	 * ----- Internal Utilities -----
	**/

	private heap_copyBuffer(ptr: number, num_bytes: number): Uint8Array
	{
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

	public util_concatBuffers(buffers: Array<Readonly<Uint8Array>>): Uint8Array
	{
		const totalByteLength = buffers.reduce<number>((total, buffer)=> {
			return (total + buffer.byteLength);
		}, 0);
	
		const result = new Uint8Array(totalByteLength);
		let offset = 0;
	
		for (const buffer of buffers)
		{
			result.set(buffer, offset);
			offset += buffer.length;
		}
	
		return result;
	}

	public util_compareBuffers(bufferA: Readonly<Uint8Array>, bufferB: Readonly<Uint8Array>): boolean
	{
		if (bufferA == bufferB) {
			return true;
		}

		if (bufferA.byteLength != bufferB.byteLength) {
			return false;
		}

		for (let i = 0; i < bufferA.byteLength; i++)
		{
			if (bufferA[i] != bufferB[i]) {
				return false;
			}
		}

		return true;
	}

	public util_hexString(buffer: Readonly<Uint8Array>): string
	{
		return Array.prototype.map.call(buffer, (x: number)=> ('00' + x.toString(16)).slice(-2)).join('');
	}
}
