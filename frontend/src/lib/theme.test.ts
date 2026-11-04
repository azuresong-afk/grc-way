import { applyTheme, loadTheme, saveTheme, THEME_KEY } from "./theme";

describe("тема", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
  });

  it("по умолчанию тёмная", () => {
    expect(loadTheme()).toBe("dark");
  });

  it("читает прежний ключ «Сканера», если общего ещё нет", () => {
    localStorage.setItem("scanner.theme", "light");
    expect(loadTheme()).toBe("light");
  });

  it("общий ключ платформы важнее прежнего", () => {
    localStorage.setItem("scanner.theme", "light");
    saveTheme("dark");
    expect(localStorage.getItem(THEME_KEY)).toBe("dark");
    expect(loadTheme()).toBe("dark");
  });

  it("светлая тема — атрибут data-theme на <html>", () => {
    applyTheme("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    applyTheme("dark");
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });
});
