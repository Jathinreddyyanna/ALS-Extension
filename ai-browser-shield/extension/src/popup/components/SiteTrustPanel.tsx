import { ChevronDown, ShieldCheck } from 'lucide-react';
import { useState } from 'react';

export const SiteTrustPanel = ({ domain }: { domain: string }) => {
  const [open, setOpen] = useState(false);

  return (
    <div className="surface-card p-4">
      <div className="flex items-center gap-3">
        <div className="rounded-full bg-safe-600/12 p-3 text-safe-600 dark:bg-safe-dark/12 dark:text-safe-dark">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div>
          <p className="subheading">Trusted site</p>
          <p className="caption">{domain}</p>
        </div>
      </div>
      <button type="button" onClick={() => setOpen((value) => !value)} className="mt-3 inline-flex items-center gap-2 text-caption text-safe-600 dark:text-safe-dark">
        Why is this trusted?
        <ChevronDown className={`h-4 w-4 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <p className="caption mt-3">
          This site matches a known trusted domain and does not show strong warning signs. Trusted sites can still be abused, so we keep checking quietly in the background.
        </p>
      )}
    </div>
  );
};
