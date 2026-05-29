// Minimal shared CLI argv helpers. Used by the entry-point scripts
// (ticker-node, notary, publisher, bake-installer) so each doesn't
// hand-roll the same trio of lookups.

export const flagPresent = (argv: ReadonlyArray<string>, name: string): boolean =>
  argv.includes(name);

export const flagValue = (
  argv: ReadonlyArray<string>,
  ...names: ReadonlyArray<string>
): string | undefined => {
  for (const n of names) {
    const i = argv.indexOf(n);
    if (i >= 0 && argv[i + 1] !== undefined) return argv[i + 1];
  }
  return undefined;
};

export const flagAll = (argv: ReadonlyArray<string>, name: string): string[] => {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === name && argv[i + 1] !== undefined) out.push(argv[i + 1]!);
  }
  return out;
};
