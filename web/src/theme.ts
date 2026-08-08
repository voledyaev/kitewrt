/** Colour scheme: light, dark, or follow the OS.
 *
 *  Self-contained on purpose — no dependency, no network, and the resolve step
 *  is duplicated as an inline script in index.html so the correct theme is on
 *  <html> before first paint. Without that the page renders dark, then flips,
 *  which on a phone at night is genuinely unpleasant.
 */
export type ThemeChoice = "system" | "light" | "dark";

const KEY = "kitewrt-theme";
const DARK = "kitewrt";
const LIGHT = "kitewrt-light";

export function readChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system"; // private mode / storage disabled — follow the OS
  }
}

export function systemPrefersDark(): boolean {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? true;
}

export function applyChoice(choice: ThemeChoice): void {
  const dark = choice === "system" ? systemPrefersDark() : choice === "dark";
  document.documentElement.setAttribute("data-theme", dark ? DARK : LIGHT);
}

export function saveChoice(choice: ThemeChoice): void {
  try {
    if (choice === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, choice);
  } catch {
    // Non-fatal: the theme still applies for this page load.
  }
}

/** Re-apply when the OS flips, but only while following it. */
export function watchSystem(onChange: () => void): () => void {
  const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
  if (!mq) return () => {};
  const handler = () => {
    if (readChoice() === "system") onChange();
  };
  mq.addEventListener("change", handler);
  return () => mq.removeEventListener("change", handler);
}
