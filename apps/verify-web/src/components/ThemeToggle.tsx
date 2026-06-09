import { useEffect, useState } from "react";
import {
	applyTheme,
	getStoredTheme,
	type Theme,
	toggleTheme,
} from "../lib/theme";

export function ThemeToggle() {
	const [theme, setTheme] = useState<Theme>(() => getStoredTheme());

	useEffect(() => {
		applyTheme(theme);
	}, [theme]);

	return (
		<button
			type="button"
			className="theme-toggle"
			onClick={() => setTheme((current) => toggleTheme(current))}
			aria-label={
				theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
			}
		>
			{theme === "dark" ? "Light mode" : "Dark mode"}
		</button>
	);
}
