import { ChevronLeft, ChevronRight } from "lucide-react";
import { formatNumber } from "../lib/format";

interface Props {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}

export function Pager({ total, limit, offset, onChange }: Props) {
  if (total <= limit) return null;
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className="pager">
      <span>
        {formatNumber(from)}–{formatNumber(to)} из {formatNumber(total)}
      </span>
      <button
        type="button"
        className="icon-btn"
        aria-label="Предыдущая страница"
        disabled={offset === 0}
        onClick={() => onChange(Math.max(0, offset - limit))}
      >
        <ChevronLeft size={15} />
      </button>
      <button
        type="button"
        className="icon-btn"
        aria-label="Следующая страница"
        disabled={to >= total}
        onClick={() => onChange(offset + limit)}
      >
        <ChevronRight size={15} />
      </button>
    </div>
  );
}
