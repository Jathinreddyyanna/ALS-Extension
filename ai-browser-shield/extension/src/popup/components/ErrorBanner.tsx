export const ErrorBanner = ({ message, onRetry }: { message: string; onRetry?: () => void }) => (
  <div className="rounded-md border border-danger-600/20 bg-danger-50 px-4 py-3 text-caption text-danger-700 dark:bg-danger-600/10 dark:text-danger-400">
    <div className="flex items-start justify-between gap-3">
      <span>{message}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} className="font-semibold underline underline-offset-2">
          Retry
        </button>
      )}
    </div>
  </div>
);
