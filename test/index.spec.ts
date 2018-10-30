import { expect } from 'chai';
import 'mocha';
import * as _ from 'lodash';

import {
	S4,
	S4HashAlgorithm,
	S4Err
} from '../dist/index'

/**
 * NOTES:
 * 
 * This is not designed to be an extensive test-suite for the underlying crypto algorithms.
 * That task is already handled by S4,
 * which comes with it's own test suite both for native builds & for WebAssembly builds.
 * 
 * You can run the S4 WebAssembly tests via (from within the S4 repository):
 * $ make em_test
 * 
 * Our focus here is on making sure the Javascript wrapper works properly.
**/

let global_s4: S4|null = null;

function loadS4(
	callback: (
		err  : Error|null,
		s4  ?: S4
	)=> void
): void
{
	if (global_s4 != null)
	{
		const s4 = global_s4;
		setImmediate(()=> {
			callback(null, s4);
		});
		return;
	}

	interface S4Global {
		onModuleS4Initialized: Array<() => void>
		ModuleS4: {
			isRuntimeInitialized: boolean,
			onRuntimeInitialized: ()=>void,
			print: (text: string)=>void,
			printErr: (text: string)=>void
		}
	}
	const s4global = ((global as unknown) as S4Global);

	if (s4global.onModuleS4Initialized == null)
	{
		s4global.onModuleS4Initialized = [];
	}
	
	if (s4global.ModuleS4 == null)
	{
		s4global.ModuleS4 = {
			isRuntimeInitialized: false,
			onRuntimeInitialized: ()=> {
			
				s4global.ModuleS4.isRuntimeInitialized = true;
				try
				{
					for (let i = 0; i < s4global.onModuleS4Initialized.length; i++)
					{
						const listener = s4global.onModuleS4Initialized[i];
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
		
		require('../dist/libS4.js');

		const wasmReady = ()=> {
			
			const s4 = S4.load(s4global.ModuleS4);
			if (s4 == null)
			{
				callback(new Error("Unable to load S4 !"));
			}
			else
			{
				global_s4 = s4;
				callback(null, s4);
			}
		}

		if (s4global.ModuleS4.isRuntimeInitialized) {
			wasmReady();
		}
		else {
			console.log("Waiting for WASM crypto library...");
			s4global.onModuleS4Initialized.push(wasmReady);
		}
	}
}

describe('load S4', ()=> {

	it('callback', (done)=> {

		loadS4((err, s4)=> {

			expect(err).to.be.null;
			expect(s4).to.be.not.null;

			done();
		});
	});
});

describe('version', ()=>{

	it('callback', (done)=> {

		loadS4((err, s4)=> {

			expect(err).to.be.null;
			expect(s4).to.be.not.null;

			s4 = s4!;

			const version = s4.version();
			expect(version).to.be.not.null;

			console.log("S4 version: "+ version);
			done();
		});
	});
});

// A good independent verifier:
// https://emn178.github.io/online-tools/sha3_224.html
// 
interface HashTestSuite {
	algorithm : S4HashAlgorithm,
	input     : string,
	output    : string
}
const hashTestSuite: HashTestSuite[] = [
	{
		algorithm : S4HashAlgorithm.MD5,
		input     : "Hello World",
		output    : "b10a8db164e0754105b7a99be72e3fe5"
	},
	{
		algorithm : S4HashAlgorithm.SHA1,
		input     : "Hello World",
		output    : "0a4d55a8d778e5022fab701977c5d840bbc486d0"
	},
	{
		algorithm : S4HashAlgorithm.SHA224,
		input     : "Hello World",
		output    : "c4890faffdb0105d991a461e668e276685401b02eab1ef4372795047"
	},
	{
		algorithm : S4HashAlgorithm.SHA256,
		input     : "Hello World",
		output    : "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
	},
	{
		algorithm : S4HashAlgorithm.SHA384,
		input     : "Hello World",
		output    : "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f"
	},
	{
		algorithm : S4HashAlgorithm.SHA512,
		input     : "Hello World",
		output    : "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b"
	},
	{
		algorithm : S4HashAlgorithm.SHA512_256,
		input     : "Hello World",
		output    : "ff20018851481c25bfc2e5d0c1e1fa57dac2a237a1a96192f99a10da47aa5442"
	},
	{
		algorithm : S4HashAlgorithm.SKEIN256,
		input     : "0xFFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
		output    : "8d0fa4ef777fd759dfd4044e6f6a5ac3c774aec943dcfc07927b723b5dbf408b"
	},
	{
		algorithm : S4HashAlgorithm.SKEIN512,
		input     : "0xFFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
		output    : "0b7fd053ae635ee8e519646eb41ea0cf7ea340152378062fb2440aa0250ff195fe32d9a0691e68a0feb17dc285aa6756cef19404e4db92bf836c4ae65381504a"
	},
	{
		algorithm : S4HashAlgorithm.SKEIN1024,
		input     : "0xFFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
		output    : "d9f381eaada57d8f407a01d876e6b3c2093418a486045f7ce23a90150d9316013bb54e5638b372e375597289cf7450eb4789b5553e2b2947d2aa81097f4a8e84d39e0fca2f30b5ee7a8ed73c31f78b5804b6ef79f57fe443afba1151cc48e0191ac625e9d5f72b843d7710b29e7f989d8d3fc21bba49d46b9f75a07b2208673c"
	},
	{
		algorithm : S4HashAlgorithm.xxHash32,
		input     : "0x9eff1f4b5e532fddb5544d2a952b",
		output    : "1D958144"
	},
	{
		algorithm : S4HashAlgorithm.xxHash64,
		input     : "0x9eff1f4b5e532fddb5544d2a952b",
		output    : "CBC9FC5E5811965B"
	},
	{
		algorithm : S4HashAlgorithm.SHA3_224,
		input     : "Hello World",
		output    : "8e800079a0b311788bf29353f400eff969b650a3597c91efd9aa5b38"
	},
	{
		algorithm : S4HashAlgorithm.SHA3_256,
		input     : "Hello World",
		output    : "e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51"
	},
	{
		algorithm : S4HashAlgorithm.SHA3_384,
		input     : "Hello World",
		output    : "a78ec2851e991638ce505d4a44efa606dd4056d3ab274ec6fdbac00cde16478263ef7213bad5a7db7044f58d637afdeb"
	},
	{
		algorithm : S4HashAlgorithm.SHA3_512,
		input     : "Hello World",
		output    : "3d58a719c6866b0214f96b0a67b37e51a91e233ce0be126a08f35fdf4c043c6126f40139bfbc338d44eb2a03de9f7bb8eff0ac260b3629811e389a5fbee8a894"
	},
];

describe('hash_do', ()=> {

	it('callback', (done)=> {
	
		loadS4((err, s4)=> {

			expect(err).to.be.null;
			expect(s4).to.be.not.null;

			s4 = s4!;
		
			for (const test of hashTestSuite)
			{
				let inputStr = test.input;
				let inputStrType = 'utf8'

				if (inputStr.startsWith('0x') || inputStr.startsWith('0X'))
				{
					inputStr = inputStr.substr(2);
					inputStrType = 'hex';
				}
				
				const inputBuffer = Buffer.from(inputStr, inputStrType);
				const inputData = Uint8Array.from(inputBuffer);

				const outputData = s4.hash_do(test.algorithm, inputData);
				expect(outputData).to.be.not.null;

				if (outputData)
				{
					const outputStr = s4.util_hexString(outputData);
					console.log(`- ${_.padStart(S4HashAlgorithm[test.algorithm], 10)}: `+ outputStr);

					expect(outputStr).to.equal(test.output.toLowerCase());
				}
			}
		
			done();
		});
	});
});

describe('hash_stream', ()=> {

	it('callback', (done)=> {
	
		loadS4((err, s4)=> {

			expect(err).to.be.null;
			expect(s4).to.be.not.null;

			s4 = s4!;
		
			for (const test of hashTestSuite)
			{
				const context = s4.hash_init(test.algorithm)!;
				expect(context).to.be.not.null;

				let inputStr = test.input;
				let inputStrType = 'utf8'

				if (inputStr.startsWith('0x') || inputStr.startsWith('0X'))
				{
					inputStr = inputStr.substr(2);
					inputStrType = 'hex';
				}
				
				const inputBuffer = Buffer.from(inputStr, inputStrType);
				const inputData = Uint8Array.from(inputBuffer);

				const err = s4.hash_update(context, inputData);
				expect(err).to.equal(S4Err.NoErr);

				const outputData = s4.hash_final(context);
				expect(outputData).to.be.not.null;

				if (outputData)
				{
					const outputStr = s4.util_hexString(outputData);
					console.log(`- ${_.padStart(S4HashAlgorithm[test.algorithm], 10)}: `+ outputStr);

					expect(outputStr).to.equal(test.output.toLowerCase());
				}

				s4.hash_free(context);
			}
		
			done();
		});
	});
});