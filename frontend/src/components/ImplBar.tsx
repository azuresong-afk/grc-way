import { barParts, type StatsBucket } from "../lib/measures";

/** Полоса реализации: реализовано · частично · не реализовано · не оценено. */
export function ImplBar({ bucket, small }: { bucket: StatsBucket | null | undefined; small?: boolean }) {
  const parts = bucket ? barParts(bucket) : [];
  return (
    <div
      className={`impl-bar${small ? " impl-bar-sm" : ""}`}
      role="img"
      aria-label={parts.map((p) => `${p.label}: ${Math.round(p.value)} %`).join(", ") || "нет мер"}
    >
      {parts.map((p) => (
        <span key={p.key} className={`impl-bar-${p.key}`} style={{ width: `${p.value}%` }} />
      ))}
    </div>
  );
}
