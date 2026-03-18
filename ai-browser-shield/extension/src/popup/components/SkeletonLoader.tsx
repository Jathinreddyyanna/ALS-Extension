export const SkeletonLoader = ({ className }: { className: string }) => (
  <div className={`shimmer rounded-md bg-[var(--surface-alt)] ${className}`} aria-hidden="true" />
);
