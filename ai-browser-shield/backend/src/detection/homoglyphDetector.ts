const latinPattern = /[A-Za-z]/u;
const cyrillicPattern = /[\u0400-\u04FF]/u;
const greekPattern = /[\u0370-\u03FF]/u;

export const hasMixedScriptHostname = (hostname: string): boolean => {
  const value = hostname.normalize('NFKC');
  const hasLatin = latinPattern.test(value);
  const hasCyrillic = cyrillicPattern.test(value);
  const hasGreek = greekPattern.test(value);
  return Number(hasLatin) + Number(hasCyrillic) + Number(hasGreek) > 1;
};
