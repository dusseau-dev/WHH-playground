/** Relay a parent cancellation signal to a Pi session and return listener cleanup. */
export function attachCancellation(signal: AbortSignal | undefined, abort: () => void | Promise<void>): () => void {
  if (!signal) return () => undefined;
  const onAbort = (): void => {
    void Promise.resolve(abort()).catch(() => {
      // Cancellation is best-effort; session disposal is the final teardown.
    });
  };
  if (signal.aborted) onAbort();
  else signal.addEventListener('abort', onAbort, { once: true });
  return () => signal.removeEventListener('abort', onAbort);
}
