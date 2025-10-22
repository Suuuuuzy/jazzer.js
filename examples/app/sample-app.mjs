// Sample app module that should be instrumented
export function add(a, b) {
	return a + b;
}

export function multiply(x, y) {
	const result = x * y;
	return result;
}

export class Calculator {
	constructor() {
		this.history = [];
	}

	calculate(operation, a, b) {
		let result;
		switch (operation) {
			case "add":
				result = add(a, b);
				break;
			case "multiply":
				result = multiply(a, b);
				break;
			default:
				throw new Error("Unknown operation");
		}
		this.history.push({ operation, a, b, result });
		return result;
	}
}

export default {
	add,
	multiply,
	Calculator,
};
