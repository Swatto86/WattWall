/** Whether a search box should keep this program visible. */
export function matches(name: string, path: string, publisher: string, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return (
    name.toLowerCase().includes(needle) ||
    path.toLowerCase().includes(needle) ||
    publisher.toLowerCase().includes(needle)
  );
}
