import { useQuery } from '@tanstack/react-query';
import { getCurrentTab } from '@/lib/chrome';

export const useCurrentTab = () =>
  useQuery({
    queryKey: ['current-tab'],
    queryFn: getCurrentTab,
    staleTime: 30_000
  });
