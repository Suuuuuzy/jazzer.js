/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export type FuzzTargetAsyncOrValue = (
	data: Buffer,
) => unknown | Promise<unknown>;
export type FuzzTargetCallback = (
	data: Buffer,
	done: (e?: Error) => void,
) => unknown;
export type FuzzTarget = FuzzTargetAsyncOrValue | FuzzTargetCallback;
export type FuzzOpts = string[];

export type StartFuzzingSyncFn = (
	fuzzFn: FuzzTarget,
	fuzzOpts: FuzzOpts,
	jsStopCallback: (signal: number) => void,
) => Promise<void>;
export type StartFuzzingAsyncFn = (
	fuzzFn: FuzzTarget,
	fuzzOpts: FuzzOpts,
) => Promise<void>;

type NativeAddon = {
	registerCoverageMap: (buffer: Buffer) => void;
	registerNewCounters: (oldNumCounters: number, newNumCounters: number) => void;

	traceUnequalStrings: (
		hookId: number,
		current: string,
		target: string,
	) => void;

	traceStringContainment: (
		hookId: number,
		needle: string,
		haystack: string,
	) => void;
	traceIntegerCompare: (
		hookId: number,
		current: number,
		target: number,
	) => void;

	tracePcIndir: (hookId: number, state: number) => void;

	printAndDumpCrashingInput: () => void;
	printReturnInfo: (sync: boolean) => void;
	printVersion: () => void;

	startFuzzing: StartFuzzingSyncFn;
	startFuzzingAsync: StartFuzzingAsyncFn;
};

// Load the native addon based on the runtime environment
let addon: NativeAddon;

if (process.versions.electron !== undefined) {
	// case 1: electron
	// Use dlopen to load the native addon with Electron-compatible path resolution
	try {
		const path = require("path");
		const addonPath = path.join(
			(process as any).resourcesPath,
			"jazzerjs.node",
		);
		const module = { exports: {} as any };
		(process as any).dlopen(module, addonPath);
		addon = module.exports as NativeAddon;
	} catch (error) {
		console.warn(
			"[jazzer.js] Failed to load jazzerjs.node from Electron resources",
		);
		throw error;
	}
} else {
	// case 0: node
	const bind = require("bindings");
	addon = bind("jazzerjs");
}

export { addon };
