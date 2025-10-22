import { FuzzedDataProvider } from "@jazzer.js/core";
import { handleUrl } from "./handler.ts";
import { generateUrlPath } from "./urlGenerator.js";
import fs from "fs";
import path from "path";

// Create a log file with timestamp in examples/eidos directory
const logFile = path.join(
	"/Users/susie/Desktop/electron_exp/jazzer.js/examples/eidos",
	`fuzz-urls-${new Date().toISOString().replace(/[:.]/g, "-")}.log`,
);

/**
 * @param {string} message
 */
function logToFile(message) {
	const timestamp = new Date().toISOString();
	const logEntry = `[${timestamp}] ${message}\n`;
	fs.appendFileSync(logFile, logEntry);
}

// Log the start of fuzzing session
logToFile(`=== Fuzzing session started ===`);
console.log(`Logging URLs to: ${logFile}`);

/**
 * @param {Buffer} buf
 */
export function fuzz(buf) {
	// ====
	// let urlPath;
	// const provider = new FuzzedDataProvider(buf);
	// console.log("Fuzz function called with buffer of length:", buf.length);

	// // Generate URL path using proper URL character specifications
	// urlPath = generateUrlPath(provider);

	// if (urlPath.length === 0) {
	// 	return;
	// }
	// ====

	let urlPath;
	// const provider = new FuzzedDataProvider(buf);
	try {
		urlPath = Buffer.isBuffer(buf)
			? buf.toString("utf8")
			: Buffer.from(buf).toString("utf8");
	} catch {
		urlPath = Buffer.isBuffer(buf)
			? buf.toString("latin1")
			: Buffer.from(buf).toString("latin1");
	}

	const protocol = "electron";
	const urlVariants = [
		`${protocol}://${urlPath}`,
		`${protocol}:${urlPath}`, // No slashes
	];
	console.log("Testing URL variants:", urlVariants);
	logToFile(`Generated URLs: ${urlVariants.join(", ")}`);

	for (const url of urlVariants) {
		try {
			new URL(url);
			console.log("Calling handleUrl with:", url);
			logToFile(`Testing URL: ${url}`);
			handleUrl(url);
		} catch (error) {
			const errorMsg = error instanceof Error ? error.message : String(error);
			logToFile(`ERROR: ${url} - ${errorMsg}`);
			// Don't rethrow - let fuzzing continue with other URLs
		}
	}

	console.log("Fuzz function completed");
}
