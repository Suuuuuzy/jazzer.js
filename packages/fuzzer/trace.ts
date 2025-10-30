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

import { addon } from "./addon";

/**
 * Performs a string comparison between two strings and calls the corresponding native hook if needed.
 * This function replaces the original comparison expression and preserves the semantics by returning
 * the original result after calling the native hook.
 * @param s1 first compared string. s1 has the type `unknown` because we can only know the type at runtime.
 * @param s2 second compared string. s2 has the type `unknown` because we can only know the type at runtime.
 * @param operator the operator used in the comparison
 * @param id an unique identifier to distinguish between the different comparisons
 * @returns result of the comparison
 */
function traceStrCmp(
	s1: unknown,
	s2: unknown,
	operator: string,
	id: number,
): boolean {
	let result = false;
	let shouldCallLibfuzzer = false;
	switch (operator) {
		case "==":
			result = s1 == s2;
			shouldCallLibfuzzer = !result;
			break;
		case "===":
			result = s1 === s2;
			shouldCallLibfuzzer = !result;
			break;
		case "!=":
			result = s1 != s2;
			shouldCallLibfuzzer = result;
			break;
		case "!==":
			result = s1 !== s2;
			shouldCallLibfuzzer = result;
			break;
	}
	if (
		shouldCallLibfuzzer &&
		s1 &&
		s2 &&
		typeof s1 === "string" &&
		typeof s2 === "string"
	) {
		addon.traceUnequalStrings(id, s1, s2);
	}
	return result;
}

/**
 * Performs an integer comparison between two strings and calls the corresponding native hook if needed.
 * This function replaces the original comparison expression and preserves the semantics by returning
 * the original result after calling the native hook.
 * @param n1 first compared number
 * @param n2 second compared number
 * @param operator the operator used in the comparison
 * @param id an unique identifier to distinguish between the different comparisons
 * @returns result of the comparison
 */
function traceNumberCmp(
	n1: number,
	n2: number,
	operator: string,
	id: number,
): boolean {
	if (Number.isInteger(n1) && Number.isInteger(n2)) {
		addon.traceIntegerCompare(id, n1, n2);
	}
	switch (operator) {
		case "==":
			return n1 == n2;
		case "===":
			return n1 === n2;
		case "!=":
			return n1 != n2;
		case "!==":
			return n1 !== n2;
		case ">":
			return n1 > n2;
		case ">=":
			return n1 >= n2;
		case "<":
			return n1 < n2;
		case "<=":
			return n1 <= n2;
		default:
			throw `unexpected number comparison operator ${operator}`;
	}
}

function traceAndReturn(current: unknown, target: unknown, id: number) {
	switch (typeof target) {
		case "number":
			if (typeof current === "number") {
				if (Number.isInteger(current) && Number.isInteger(target)) {
					addon.traceIntegerCompare(id, current, target);
				}
			}
			break;
		case "string":
			if (typeof current === "string") {
				addon.traceUnequalStrings(id, current, target);
			}
	}
	return target;
}

/**
 * Traces Array.prototype.includes() calls to guide the fuzzer.
 * This function replaces array.includes(searchElement) and preserves semantics
 * while providing comparison hints to the fuzzer for each array element.
 *
 * @param arr the array to search in
 * @param searchElement the element to search for
 * @param id an unique identifier to distinguish between different includes calls
 * @returns result of the includes operation
 */
function traceArrayIncludes(
	arr: unknown,
	searchElement: unknown,
	id: number,
): boolean {
	// Validate that arr is actually an array
	if (!Array.isArray(arr)) {
		return false;
	}

	// Check if the array includes the search element
	const result = arr.includes(searchElement);

	// Trace comparisons with each array element to guide the fuzzer
	// This helps the fuzzer understand what values would satisfy the includes check
	if (typeof searchElement === "string") {
		for (const element of arr) {
			if (typeof element === "string") {
				addon.traceUnequalStrings(id, searchElement, element);
			}
		}
	} else if (
		typeof searchElement === "number" &&
		Number.isInteger(searchElement)
	) {
		for (const element of arr) {
			if (typeof element === "number" && Number.isInteger(element)) {
				addon.traceIntegerCompare(id, searchElement, element);
			}
		}
	}

	return result;
}

/**
 * Traces Array.prototype.indexOf() calls to guide the fuzzer.
 * This function replaces array.indexOf(searchElement) and preserves semantics
 * while providing comparison hints to the fuzzer for each array element.
 *
 * @param arr the array to search in
 * @param searchElement the element to search for
 * @param id an unique identifier to distinguish between different indexOf calls
 * @returns the index of the element, or -1 if not found
 */
function traceArrayIndexOf(
	arr: unknown,
	searchElement: unknown,
	id: number,
): number {
	// Validate that arr is actually an array
	if (!Array.isArray(arr)) {
		return -1;
	}

	// Get the index
	const result = arr.indexOf(searchElement);

	// Trace comparisons with each array element to guide the fuzzer
	if (typeof searchElement === "string") {
		for (const element of arr) {
			if (typeof element === "string") {
				addon.traceUnequalStrings(id, searchElement, element);
			}
		}
	} else if (
		typeof searchElement === "number" &&
		Number.isInteger(searchElement)
	) {
		for (const element of arr) {
			if (typeof element === "number" && Number.isInteger(element)) {
				addon.traceIntegerCompare(id, searchElement, element);
			}
		}
	}

	return result;
}

/**
 * Traces String.prototype.split() calls to guide the fuzzer.
 * This function replaces string.split(separator) and preserves semantics
 * while providing hints to the fuzzer about the delimiter and expected string structure.
 *
 * @param str the string to split
 * @param separator the delimiter string or regex
 * @param limitOrId if called with 3 args: id, if called with 4 args: limit
 * @param id optional unique identifier (present when limit is used)
 * @returns array of substrings
 */
function traceStringSplit(
	str: unknown,
	separator: unknown,
	limitOrId?: unknown,
	id?: number,
): string[] {
	// Determine if limit was provided based on number of arguments
	// If 4 arguments: str, separator, limit, id
	// If 3 arguments: str, separator, id
	const hasLimit = id !== undefined;
	const actualId = hasLimit ? id : (limitOrId as number);
	const limit = hasLimit ? (limitOrId as number | undefined) : undefined;

	// Type check
	if (typeof str !== "string") {
		return [];
	}

	// Perform the actual split operation
	let result: string[];
	if (separator instanceof RegExp) {
		result =
			limit !== undefined ? str.split(separator, limit) : str.split(separator);
	} else if (typeof separator === "string") {
		result =
			limit !== undefined ? str.split(separator, limit) : str.split(separator);

		// Trace the separator for string containment
		// This helps the fuzzer understand that 'str' should contain 'separator'
		if (separator.length > 0) {
			addon.traceStringContainment(actualId, separator, str);
		}
	} else {
		// Fallback for unexpected separator types
		result =
			limit !== undefined
				? str.split(separator as any, limit)
				: str.split(separator as any);
	}

	return result;
}

export interface Tracer {
	traceStrCmp: typeof traceStrCmp;
	traceUnequalStrings: typeof addon.traceUnequalStrings;
	traceStringContainment: typeof addon.traceStringContainment;
	traceNumberCmp: typeof traceNumberCmp;
	traceAndReturn: typeof traceAndReturn;
	traceStringSplit: typeof traceStringSplit;
	traceArrayIncludes: typeof traceArrayIncludes;
	traceArrayIndexOf: typeof traceArrayIndexOf;
	tracePcIndir: typeof addon.tracePcIndir;
	guideTowardsEquality: typeof guideTowardsEquality;
	guideTowardsContainment: typeof guideTowardsContainment;
	exploreState: typeof exploreState;
}

export const tracer: Tracer = {
	traceStrCmp,
	traceUnequalStrings: addon.traceUnequalStrings,
	traceStringContainment: addon.traceStringContainment,
	traceNumberCmp,
	traceAndReturn,
	traceStringSplit,
	traceArrayIncludes,
	traceArrayIndexOf,
	tracePcIndir: addon.tracePcIndir,
	guideTowardsEquality: guideTowardsEquality,
	guideTowardsContainment: guideTowardsContainment,
	exploreState: exploreState,
};

/**
 * Instructs the fuzzer to guide its mutations towards making `current` equal to `target`
 *
 * If the relation between the raw fuzzer input and the value of `current` is relatively
 * complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
 * achieve equality.
 *
 * @param current a non-constant string observed during fuzz target execution
 * @param target a string that `current` should become equal to, but currently isn't
 * @param id a (probabilistically) unique identifier for this particular compare hint
 */
function guideTowardsEquality(current: string, target: string, id: number) {
	// Check types as JavaScript fuzz targets could provide wrong ones.
	// noinspection SuspiciousTypeOfGuard
	if (
		typeof current !== "string" ||
		typeof target !== "string" ||
		typeof id !== "number"
	) {
		return;
	}
	tracer.traceUnequalStrings(id, current, target);
}

/**
 * Instructs the fuzzer to guide its mutations towards making `haystack` contain `needle` as a substring.
 *
 * If the relation between the raw fuzzer input and the value of `haystack` is relatively
 * complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
 * satisfy the substring check.
 *
 * @param needle a string that should be contained in `haystack` as a substring, but
 *     currently isn't
 * @param haystack a non-constant string observed during fuzz target execution
 * @param id a (probabilistically) unique identifier for this particular compare hint
 */
function guideTowardsContainment(needle: string, haystack: string, id: number) {
	// Check types as JavaScript fuzz targets could provide wrong ones.
	// noinspection SuspiciousTypeOfGuard
	if (
		typeof needle !== "string" ||
		typeof haystack !== "string" ||
		typeof id !== "number"
	) {
		return;
	}
	tracer.traceStringContainment(id, needle, haystack);
}

/**
 * Instructs the fuzzer to attain as many possible values for the absolute value of `state`
 * as possible.
 *
 * Call this function from a fuzz target or a hook to help the fuzzer track partial progress
 * (e.g. by passing the length of a common prefix of two lists that should become equal) or
 * explore different values of state that is not directly related to code coverage.
 *
 * Note: This hint only takes effect if the fuzzer is run with the argument
 * `-use_value_profile=1`.
 *
 * @param state a numeric encoding of a state that should be varied by the fuzzer
 * @param id a (probabilistically) unique identifier for this particular state hint
 */
export function exploreState(state: number, id: number) {
	// Check types as JavaScript fuzz targets could provide wrong ones.
	// noinspection SuspiciousTypeOfGuard
	if (typeof state !== "string" || typeof id !== "number") {
		return;
	}
	tracer.tracePcIndir(id, state);
}
