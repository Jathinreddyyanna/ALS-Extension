import { useQuery, type UseQueryOptions } from '@tanstack/react-query';

export const useApiRequest = <TData>(options: UseQueryOptions<TData>) => useQuery(options);
