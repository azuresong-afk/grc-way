import { formatDateTime } from "../lib/format";

/** Отметка «Сверено методистом» / «требует сверки». */
export function VerifyBadge({
  verified,
  by,
  at,
}: {
  verified: boolean;
  by?: string | null;
  at?: string | null;
}) {
  if (verified) {
    return (
      <span className="pill pill-ok" title={by ? `${by}, ${formatDateTime(at)}` : undefined}>
        Сверено
      </span>
    );
  }
  return <span className="pill pill-warn">Требует сверки</span>;
}
