export const ROLE_TITLES: Record<string, string> = {
  admin: "Администратор",
  methodologist: "Методист",
  assessor: "Эксперт",
  viewer: "Наблюдатель",
  approve: "Утверждающий",
};

export const ROLE_HINTS: Record<string, string> = {
  admin: "Пользователи, справочники, интеграции, журнал. Рабочих операций не выполняет",
  methodologist: "Объекты, классификация, адаптация, модель угроз, документы",
  assessor: "Оценка мер, доказательства, протоколы испытаний",
  viewer: "Просмотр и выгрузка утверждённых документов (представитель заказчика)",
  approve: "Надбавка к рабочей роли: утверждение класса, адаптации, заключения",
};

export const ROLE_ORDER = ["methodologist", "assessor", "viewer", "approve", "admin"];

export function roleList(roles: string[]): string {
  return [...roles]
    .sort((a, b) => ROLE_ORDER.indexOf(a) - ROLE_ORDER.indexOf(b))
    .map((r) => ROLE_TITLES[r] ?? r)
    .join(", ");
}
