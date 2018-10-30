// In your project, you'll do this instead:
// import {S4, S4Module} from 's4js';
import {S4, S4Module, S4HashAlgorithm} from '../../dist.browser/index.js';

// If using Typescript, add these for the compiler:
interface ModuleLoader extends S4Module {
	isRuntimeInitialized: boolean
}
declare var onModuleS4Initialized: Array<()=>void>;
declare var ModuleS4: ModuleLoader;

// And then add this somewhere to initialize S4
const wasmReady = ()=> {

	const s4 = S4.load(ModuleS4);
	if (s4 == null)
	{
		console.log("Failed loading WASM crypto library !");
	}
	else
	{
		console.log("WASM crypto library ready");
		playWithS4(s4);
	}
}

if (ModuleS4.isRuntimeInitialized) {
	wasmReady();
}
else {
	console.log("Waiting for WASM crypto library...");
	onModuleS4Initialized.push(wasmReady);
}

function playWithS4(s4: S4): void
{
	const str = "Hello World";
	const utf8encoder = new TextEncoder();
	const strData = utf8encoder.encode(str);

	const algo = S4HashAlgorithm.SHA3_256;
	const hashData = s4.hash_do(S4HashAlgorithm.SHA3_256, strData);
	if (hashData)
	{
		const hashStr = s4.util_hexString(hashData);
		console.log(`HASH ${S4HashAlgorithm[algo]}(${str}) = ${hashStr}`);

		// Here's a good online tool to independently verify the answer:
		// https://emn178.github.io/online-tools/sha3_256.html
	}
	else
	{
		console.log(`S4Err: ${s4.err_code}: ${s4.err_str()}`);
	}
}
