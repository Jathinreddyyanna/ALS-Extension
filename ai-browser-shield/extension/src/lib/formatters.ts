export const formatRelativeTime = (value: number | string): string => {
  const timestamp = typeof value === 'string' ? new Date(value).getTime() : value;
  const delta = Date.now() - timestamp;
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;
  if (delta < minute) return 'Just now';
  if (delta < hour) return `${Math.floor(delta / minute)} minute${Math.floor(delta / minute) === 1 ? '' : 's'} ago`;
  if (delta < day) return `${Math.floor(delta / hour)} hour${Math.floor(delta / hour) === 1 ? '' : 's'} ago`;
  return `${Math.floor(delta / day)} day${Math.floor(delta / day) === 1 ? '' : 's'} ago`;
};

export const formatDomainDisplay = (urlOrDomain: string): string => {
  try {
    if (urlOrDomain.includes('://')) {
      return new URL(urlOrDomain).hostname.replace(/^www\./, '');
    }
  } catch {
    return urlOrDomain.replace(/^www\./, '');
  }
  return urlOrDomain.replace(/^www\./, '');
};

export const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
};

export const formatProtectedSince = (value: number): string =>
  new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' }).format(value);
