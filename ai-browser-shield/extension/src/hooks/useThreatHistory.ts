import { useEffect, useState } from 'react';
import { getStorageLocal } from '@/lib/chrome';
import type { ThreatEvent } from '@/types/index';

export const useThreatHistory = () => {
  const [history, setHistory] = useState<ThreatEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    void getStorageLocal<ThreatEvent[]>('shield-history', []).then((items) => {
      setHistory(items);
      setIsLoading(false);
    });
  }, []);

  return { history, isLoading };
};
