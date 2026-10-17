// Loading data into a component: the result, the failure to show, and a way to load again.

import { type DependencyList, useCallback, useEffect, useState } from 'react';
import { errorText } from './api';
import { t } from './i18n';

/** Loads data on mount and whenever `deps` change; `reload` loads again on demand. */
export function useLoad<T>(loader: () => Promise<T>, deps: DependencyList) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const reload = useCallback(() => {
    return loader()
      .then((value) => {
        setData(value);
        setError('');
      })
      .catch((err) => setError(errorText(err, t('Failed to load'))));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, setError, reload };
}

/** useLoad for a list, which is empty until it has loaded. */
export function useList<T>(loader: () => Promise<T[]>) {
  const { data, ...rest } = useLoad(loader, [loader]);
  return { items: data ?? [], ...rest };
}
