// CommonJS module that can be required
const fs = require("fs");
const path = require("path");
const a = 2;

if (a > 1) {
	console.log("in utils.js");
} else {
	console.log("in utils.js else");
}
// Some utility functions
function getFileInfo(filePath) {
	try {
		const stats = fs.statSync(filePath);
		return {
			exists: true,
			size: stats.size,
			modified: stats.mtime,
			isFile: stats.isFile(),
			isDirectory: stats.isDirectory(),
		};
	} catch (error) {
		return {
			exists: false,
			error: error.message,
		};
	}
}

function logMessage(message, level = "info") {
	const timestamp = new Date().toISOString();
	console.log(`[${timestamp}] [${level.toUpperCase()}] ${message}`);
}

function delay(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

// Export using CommonJS syntax
module.exports = {
	getFileInfo,
	logMessage,
	delay,
	// You can also export individual functions
	version: "1.0.0",
};
