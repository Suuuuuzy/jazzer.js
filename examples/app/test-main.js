// Test file that imports and uses the sample app
import { add, multiply, Calculator } from "./sample-app.mjs";
// import * as test from './node_modules/test.js';
import { createRequire } from "module";

// Create require function to use CommonJS modules
const moduleRequire = createRequire(import.meta.url);
const utils = moduleRequire("./utils.js");

export function fuzz(data) {
	// test.test();

	// Use the required CommonJS module
	utils.logMessage("Starting fuzz test", "info");
	console.log("Utils version:", utils.version);
	console.log("Testing the instrumentation hook...");

	console.log("Testing add function:", add(2, 3));
	console.log("Testing multiply function:", multiply(4, 5));

	const calc = new Calculator();
	console.log("Testing Calculator class:", calc.calculate("add", 10, 20));
	console.log("Calculator history:", calc.history);

	console.log("Hook test completed successfully!");
}
