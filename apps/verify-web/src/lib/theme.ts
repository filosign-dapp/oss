export type Theme = "dark" | "light";

const STORAGE_KEY = "filosign-verify-theme";

export function getStoredTheme(): Theme {
	try {
		const stored = localStorage.getItem(STORAGE_KEY);
		if (stored === "light" || stored === "dark") return stored;
	} catch {
		// ignore
	}
	return "dark";
}

export function applyTheme(theme: Theme): void {
	document.documentElement.classList.toggle("dark", theme === "dark");
	document.documentElement.style.colorScheme = theme;
	try {
		localStorage.setItem(STORAGE_KEY, theme);
	} catch {
		// ignore
	}
}

export function toggleTheme(current: Theme): Theme {
	const next = current === "dark" ? "light" : "dark";
	applyTheme(next);
	return next;
}
