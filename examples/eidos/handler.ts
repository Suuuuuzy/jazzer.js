export interface ProtocolUrlPayload {
	url: string;
	action?: string;
	searchParams?: Record<string, string>;
	extensionId?: string;
}

function handleBlockAction(urlObj: URL, originalUrl: string) {
	try {
		// Format: eidos://block/blockid@databaseName?params
		const pathParts = urlObj.pathname.split("/").filter((part) => part);

		if (pathParts.length === 0) {
			throw new Error(
				`Invalid block URL format, missing block ID: ${originalUrl}`,
			);
		}

		const blockInfoPart = pathParts[0];
		const blockInfo = blockInfoPart.split("@");

		if (blockInfo.length !== 2) {
			throw new Error(
				`Invalid block ID format, expected blockid@database: ${blockInfoPart}`,
			);
		}

		const blockId = blockInfo[0];
		const database = blockInfo[1];

		// Create URL to the standalone blocks page
		const currentUrl = "http://localhost:13127/"; // In real scenario, get this from app context
		const currentUrlObj = new URL(currentUrl);
		// Only keep the origin part (protocol + hostname + port)
		// // now the url change to <extensionId>.ext.<spaceId>.eidos.localhost:13127/
		// const standaloneBlockUrl = new URL(`${blockId}.ext.${database}.eidos.localhost:13127`);
		const baseUrl = currentUrlObj.origin + "/";
		// Format should be /:space/standalone-blocks/:id
		const standaloneBlockUrl = new URL(
			`${baseUrl}${database}/standalone-blocks/${blockId}`,
		);
		// Copy any additional search parameters
		urlObj.searchParams.forEach((value, key) => {
			standaloneBlockUrl.searchParams.append(key, value);
		});

		// Open the URL in a new window using shell.openExternal or window.open
		console.log(
			"Opening standalone block URL in new window:",
			standaloneBlockUrl.toString(),
		);
		eval(`window.open('${standaloneBlockUrl.toString()}', '_blank')`);
	} catch (error) {
		throw error;
	}
}

export function handleUrl(url: string) {
	console.log("Handling URL:", url);
	try {
		if (!url.startsWith(`electron:`)) {
			throw new Error(`Invalid protocol: ${url.split(":")[0]}`);
		}

		const urlObj = new URL(url);
		const action = urlObj.hostname;
		const searchParams = Object.fromEntries(urlObj.searchParams);

		// Handle block action specifically
		if (action === "block") {
			handleBlockAction(urlObj, url);
			return;
		}

		// Handle extension action
		// eidos://extension/extensionId
		// if (action === 'extension') {
		//     handleExtensionAction(urlObj, url, searchParams);
		//     return;
		// }
		// Handle regular eidos protocol actions
		// convert vault to space
		if (searchParams.vault) {
			searchParams.space = searchParams.vault;
		} else {
			searchParams.space = "default";
		}
		const payload: ProtocolUrlPayload = {
			url: url,
			action: action,
			searchParams,
		};

		console.log("Main process sending protocol-url event:", payload);
	} catch (error) {
		throw error;
	}
}
