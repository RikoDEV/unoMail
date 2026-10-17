// Tests run in English whatever the machine's locale: Node (and so tests in the node
// environment, which have no localStorage) reports the operating system's language.
try {
  localStorage.setItem('unomail.language', 'en');
} catch {
  /* no storage in this environment */
}
if (typeof navigator !== 'undefined') {
  for (const [name, value] of [['language', 'en-US'], ['languages', ['en-US']]] as const) {
    try {
      Object.defineProperty(navigator, name, { value, configurable: true });
    } catch {
      /* fixed by the environment */
    }
  }
}
