import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useToast } from '../components/ui';

/** Mutation helper: toast on success/failure and invalidate the given query keys. */
export function useAct<T = any>(fn: (arg: T) => Promise<unknown>, keys: string[], okMsg?: string, after?: (r: any) => void) {
  const qc = useQueryClient();
  const toast = useToast();
  return useMutation({
    mutationFn: fn,
    onSuccess: (r) => {
      if (okMsg) toast(okMsg);
      keys.forEach((k) => void qc.invalidateQueries({ queryKey: [k] }));
      after?.(r);
    },
    onError: (e: Error) => toast(e.message, true),
  });
}
