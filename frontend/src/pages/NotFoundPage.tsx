import { FileQuestion } from "lucide-react";
import { Link } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";

export function NotFoundPage() {
  return (
    <section className="card">
      <EmptyState
        icon={<FileQuestion size={21} />}
        title="Страница не найдена"
        text="Возможно, ссылка устарела или раздел ещё не сделан."
        action={
          <Link className="btn btn-primary" to="/summary">
            К сводке
          </Link>
        }
      />
    </section>
  );
}
