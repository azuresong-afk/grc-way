import { AlertTriangle } from "lucide-react";

export function Loading() {
  return (
    <div className="loading">
      <span className="spinner" aria-hidden="true" /> Загрузка…
    </div>
  );
}

export function ErrorAlert({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="alert alert-danger" role="alert">
      <AlertTriangle size={15} />
      <span className="alert-text">{message}</span>
      {onRetry && (
        <button type="button" className="btn btn-sm" onClick={onRetry}>
          Повторить
        </button>
      )}
    </div>
  );
}
