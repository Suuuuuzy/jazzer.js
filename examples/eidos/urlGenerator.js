/**
 * Generates a URL path using proper URL character sets
 * @param {import("@jazzer.js/core").FuzzedDataProvider} provider
 * @returns {string}
 */
export function generateUrlPath(provider) {
	// URL character sets - including unsafe chars that will be encoded
	const alphanumeric =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	const unreserved = "-_.~";
	const reserved = "!*'();:@&=+$,/?#[]";
	const unsafe = ' "<>%|'; // Characters that need encoding
	const allChars = alphanumeric + unreserved + reserved + unsafe;

	// Generate host (broader chars, some will be encoded selectively)
	const hostChars = (alphanumeric + unreserved + "@" + ' "<>%|!*()').split("");
	const hostLength = provider.consumeIntegralInRange(1, 20);
	let host = "";
	for (let i = 0; i < hostLength; i++) {
		host += provider.pickValue(hostChars);
	}
	// Encode only truly unsafe characters, preserve @ and other valid URL chars
	host = host.replace(/[<>"|{}\\^`\s]/g, (char) => encodeURIComponent(char));

	// Generate path (broader chars, some will be encoded selectively)
	const pathChars = (alphanumeric + unreserved + reserved + "@" + unsafe).split(
		"",
	);
	const pathLength = provider.consumeIntegralInRange(0, 50);
	let path = "";
	for (let i = 0; i < pathLength; i++) {
		path += provider.pickValue(pathChars);
	}
	// Encode only truly unsafe characters, preserve @ and other valid URL chars
	path = path.replace(/[<>"|{}\\^`\s]/g, (char) => encodeURIComponent(char));

	// Generate query (broader chars, some will be encoded selectively)
	const queryChars = (
		alphanumeric +
		unreserved +
		"!*'();:@&=+$,/?[]" +
		unsafe
	).split("");
	const queryLength = provider.consumeIntegralInRange(0, 50);
	let query = "";
	for (let i = 0; i < queryLength; i++) {
		query += provider.pickValue(queryChars);
	}
	// Encode only truly unsafe characters, preserve @ and other valid URL chars
	query = query.replace(/[<>"|{}\\^`\s]/g, (char) => encodeURIComponent(char));

	// Generate fragment (broader chars, some will be encoded selectively)
	const fragmentChars = (
		alphanumeric +
		unreserved +
		reserved +
		"@" +
		unsafe
	).split("");
	const fragmentLength = provider.consumeIntegralInRange(0, 20);
	let fragment = "";
	for (let i = 0; i < fragmentLength; i++) {
		fragment += provider.pickValue(fragmentChars);
	}
	// Encode only truly unsafe characters, preserve @ and other valid URL chars
	fragment = fragment.replace(/[<>"|{}\\^`\s]/g, (char) =>
		encodeURIComponent(char),
	);

	// Build URL path
	let urlPath = host;
	if (path) {
		urlPath += `/${path}`;
	}
	if (query) {
		urlPath += `?${query}`;
	}
	if (fragment) {
		urlPath += `#${fragment}`;
	}

	return urlPath;
}
