declare namespace NodeJS {
	export interface Global {
		onModuleS4Initialized: Array<() => void>
		ModuleS4: {
			isRuntimeInitialized: boolean,
			onRuntimeInitialized: ()=>void,
			print: (text: string)=>void,
			printErr: (text: string)=>void
		}
	}
}
