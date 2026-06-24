// Human-readable derived player names (design note §6, legibility).
//
// An Ed25519 pubkey is the anonymous player id, but 64 hex chars don't read as
// "a person". `playerName` maps the first four bytes of the pubkey to a stable
// adjective-animal pair (e.g. "amber-unicorn"), so the same key always renders
// the same friendly name — no lookup, no state, no extra round-trips. The raw
// hex stays the source of truth; the name is a presentation affordance only.

/** Pleasant colors / adjectives. Keep curated + ~64-long; order is load-bearing
 * (it pins the golden vectors in identity-name.test.ts — append, never reorder). */
const ADJECTIVES = [
  'amber',
  'azure',
  'crimson',
  'jade',
  'slate',
  'verdant',
  'cobalt',
  'coral',
  'golden',
  'ivory',
  'indigo',
  'lilac',
  'maroon',
  'olive',
  'onyx',
  'pearl',
  'plum',
  'ruby',
  'saffron',
  'scarlet',
  'sienna',
  'teal',
  'topaz',
  'umber',
  'violet',
  'beige',
  'bronze',
  'copper',
  'emerald',
  'fuchsia',
  'garnet',
  'hazel',
  'lime',
  'magenta',
  'mauve',
  'mint',
  'mustard',
  'navy',
  'ochre',
  'peach',
  'pewter',
  'quartz',
  'rose',
  'rust',
  'sage',
  'sand',
  'sapphire',
  'silver',
  'sky',
  'snowy',
  'steel',
  'sunny',
  'tawny',
  'turquoise',
  'velvet',
  'wheat',
  'amethyst',
  'brisk',
  'calm',
  'dapper',
  'eager',
  'fleet',
  'gentle',
  'lucky',
] as const

/** Animals. Same curation/ordering rules as ADJECTIVES. */
const ANIMALS = [
  'unicorn',
  'otter',
  'falcon',
  'lynx',
  'heron',
  'badger',
  'bison',
  'cobra',
  'crane',
  'dolphin',
  'eagle',
  'egret',
  'ferret',
  'finch',
  'fox',
  'gecko',
  'gibbon',
  'hare',
  'hawk',
  'impala',
  'ibex',
  'jaguar',
  'kestrel',
  'koala',
  'lemur',
  'leopard',
  'macaw',
  'marten',
  'mink',
  'mole',
  'moose',
  'narwhal',
  'newt',
  'ocelot',
  'orca',
  'osprey',
  'owl',
  'panda',
  'panther',
  'pelican',
  'puffin',
  'puma',
  'quail',
  'rabbit',
  'raccoon',
  'raven',
  'robin',
  'salmon',
  'seal',
  'shrew',
  'sparrow',
  'stoat',
  'swan',
  'tapir',
  'teal',
  'tiger',
  'toucan',
  'turtle',
  'viper',
  'walrus',
  'weasel',
  'wolf',
  'wombat',
  'wren',
] as const

/** Sizes exported for tests / introspection. */
export const ADJECTIVE_COUNT = ADJECTIVES.length
export const ANIMAL_COUNT = ANIMALS.length

/** Parse exactly the leading `n` bytes of a hex string; returns null if there
 * aren't enough valid hex digits. Tiny + local — no wasm dependency. */
function leadingBytes(hex: string, n: number): Uint8Array | null {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex
  if (clean.length < n * 2) return null
  const out = new Uint8Array(n)
  for (let i = 0; i < n; i++) {
    const pair = clean.slice(i * 2, i * 2 + 2)
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) return null
    out[i] = Number.parseInt(pair, 16)
  }
  return out
}

/**
 * Deterministic friendly name for an Ed25519 pubkey hex, e.g. "amber-unicorn".
 * Maps the first two bytes → adjective index, next two → animal index. Returns
 * `"anonymous"` for empty / invalid / too-short hex (fewer than 4 bytes).
 */
export function playerName(pubkeyHex: string): string {
  if (!pubkeyHex) return 'anonymous'
  const b = leadingBytes(pubkeyHex, 4)
  if (!b) return 'anonymous'
  const adj = (((b[0]! << 8) | b[1]!) % ADJECTIVES.length + ADJECTIVES.length) % ADJECTIVES.length
  const animal = (((b[2]! << 8) | b[3]!) % ANIMALS.length + ANIMALS.length) % ANIMALS.length
  return `${ADJECTIVES[adj]}-${ANIMALS[animal]}`
}
