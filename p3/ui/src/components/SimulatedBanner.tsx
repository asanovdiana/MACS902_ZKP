import { FlaskConical } from 'lucide-react';
export function SimulatedBanner() {
  return (
    <div
      role="status"
      className="flex items-center gap-2 rounded-lg border border-dashed border-fuchsia-400/50 bg-fuchsia-500/10 px-3 py-2 text-xs font-medium text-fuchsia-200"
    >
      <FlaskConical className="h-4 w-4" aria-hidden />
      UI DEVELOPMENT MODE — simulated data. No proof was generated or verified; this is not evidence
      of security.
    </div>
  );
}
