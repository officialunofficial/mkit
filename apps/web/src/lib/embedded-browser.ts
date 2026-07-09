// Best-effort detection of "embedded"/in-app WebView browsers (Instagram, TikTok,
// WeChat, Telegram-on-Android, …) that commonly block or misbehave with WebAuthn
// passkeys. This is a PROACTIVE heuristic UA sniff used to show a "open this in your
// browser" notice BEFORE the user taps a passkey button — it does not gate or disable
// anything. Some in-app browsers do support passkeys, and a false positive here would
// wrongly tell a working browser "you can't do this" instead of just an unnecessary
// suggestion, so err toward under-detecting.
//
// Coverage is inherently incomplete, and one gap is unfixable from the client:
// * Apps that inject their own UA token (Instagram, Facebook, WeChat, TikTok, …) are
//   reliably caught by name.
// * Android's built-in System WebView appends a generic `; wv)` marker regardless of
//   which app embeds it, so unbranded Android in-app browsers — including Telegram's —
//   are caught by that marker.
// * iOS has no equivalent signal. Since iOS 9, a WKWebView's default User-Agent is
//   byte-for-byte identical to Safari's unless the host app explicitly overrides it,
//   and most apps (Telegram included) don't. An iOS in-app browser is frequently
//   INDISTINGUISHABLE from real Safari by User-Agent alone — there is no reliable
//   client-side signal for that case.
const EMBEDDED_BROWSER_UA =
  /instagram|fban|fbav|fb_iab|micromessenger|line\/\d|musical_ly|bytedancewebview|tiktok|snapchat|linkedinapp|twitter for (iphone|ipad|android)|pinterest|; wv\)/i

/** Pure User-Agent check — exported so tests can probe it without touching `navigator`. */
export function isEmbeddedBrowserUA(ua: string): boolean {
  return EMBEDDED_BROWSER_UA.test(ua)
}

/**
 * A short, calm notice to show before a passkey ceremony starts, or `null` when the current browser doesn't match a
 * known in-app pattern (including the iOS gap above — `null` here is "no signal detected", not "definitely a real
 * browser"). SSR-safe: never touches `navigator` outside the browser.
 */
export function embeddedBrowserWarning(): string | null {
  if (typeof navigator === 'undefined') return null
  return isEmbeddedBrowserUA(navigator.userAgent)
    ? 'This looks like an in-app browser, which often blocks passkeys. Open this page in Safari or Chrome for the smoothest experience.'
    : null
}
