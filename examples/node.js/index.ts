import {S4, S4HashAlgorithm} from '../../dist/index';
import {TextEncoder} from 'text-encoding-utf-8'

if (global.onModuleS4Initialized == null) {
	global.onModuleS4Initialized = [];
}

if (global.ModuleS4 == null) {
	global.ModuleS4 = {
		isRuntimeInitialized: false,
		onRuntimeInitialized: ()=> {
			console.log("WASM: ModuleS4.onRuntimeInitialized()");
		
			global.ModuleS4.isRuntimeInitialized = true;
			try
			{
				for (let i = 0; i < global.onModuleS4Initialized.length; i++)
				{
					const listener = global.onModuleS4Initialized[i];
					listener();
				}
			}
			catch (e) {
				console.log("Exception while attempting to invoke listeners in onModuleS4Initialized array: "+ e);
			}
		},
		print: (text)=> {
			console.log("WASM [log]: "+ text);
		},
		printErr: (text)=> {
			console.log("WASM [err]: "+ text);
		}
	};
}

/**
 * Important: This line must be AFTER we've defined
 * our `global.onModuleS4Initialized` & `global.ModuleS4`.
 * 
 * If you move this line to the top of the file, you're going to break everything.
**/
require('../../dist/libS4.js');

const wasmReady = ()=> {

	console.log("wasmReady() !");
	
	const s4 = S4.load(global.ModuleS4);
	if (s4 == null)
	{
		console.log("Unable to load S4 !");
	}
	else
	{
		playWithS4(s4);
	}
}

if (global.ModuleS4.isRuntimeInitialized) {
	wasmReady();
}
else {
	console.log("Waiting for WASM crypto library...");
	global.onModuleS4Initialized.push(wasmReady);
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

