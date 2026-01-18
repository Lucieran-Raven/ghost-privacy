export function createMinDelay(minMs: number): () => Promise<void> {
  const start = Date.now();
  return async () => {
    const elapsed = Date.now() - start;
    if (elapsed < minMs) {
      await new Promise<void>((resolve) => setTimeout(resolve, minMs - elapsed));
    }
  };
}
