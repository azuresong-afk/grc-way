import type { ReactNode } from "react";

interface Props {
  icon: ReactNode;
  title: string;
  text: string;
  action?: ReactNode;
}

// Пустое состояние: иконка, заголовок, одна фраза, одна кнопка.
export function EmptyState({ icon, title, text, action }: Props) {
  return (
    <div className="empty">
      <div className="empty-icon" aria-hidden="true">
        {icon}
      </div>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
