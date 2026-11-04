import { formatNumber, initials } from "./format";

it("числа с неразрывным пробелом", () => {
  expect(formatNumber(98600)).toBe("98 600");
});

it("инициалы из ФИО", () => {
  expect(initials("Иванов И. И.")).toBe("ИИ");
  expect(initials("admin")).toBe("A");
});
