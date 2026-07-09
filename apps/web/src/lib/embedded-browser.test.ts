import { describe, expect, it } from 'vitest'
import { isEmbeddedBrowserUA } from './embedded-browser'

const SAFARI_IOS =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1'
const CHROME_ANDROID =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36'
const CHROME_DESKTOP =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36'
const INSTAGRAM =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 302.0.0.0.0'
const FACEBOOK = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 FBAN/FBIOS;FBAV/470.0'
const WECHAT =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.47'
const TIKTOK =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.0.0 Mobile Safari/537.36 musical_ly_2024'
const ANDROID_GENERIC_WEBVIEW =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.0.0 Mobile Safari/537.36'
const SNAPCHAT = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Snapchat/12.0'

describe('isEmbeddedBrowserUA', () => {
  it('does not flag real desktop or mobile browsers', () => {
    expect(isEmbeddedBrowserUA(SAFARI_IOS)).toBe(false)
    expect(isEmbeddedBrowserUA(CHROME_ANDROID)).toBe(false)
    expect(isEmbeddedBrowserUA(CHROME_DESKTOP)).toBe(false)
  })

  it('flags known named in-app browsers', () => {
    expect(isEmbeddedBrowserUA(INSTAGRAM)).toBe(true)
    expect(isEmbeddedBrowserUA(FACEBOOK)).toBe(true)
    expect(isEmbeddedBrowserUA(WECHAT)).toBe(true)
    expect(isEmbeddedBrowserUA(TIKTOK)).toBe(true)
    expect(isEmbeddedBrowserUA(SNAPCHAT)).toBe(true)
  })

  it('flags an unbranded Android System WebView via the generic "; wv)" marker (catches Telegram-on-Android)', () => {
    expect(isEmbeddedBrowserUA(ANDROID_GENERIC_WEBVIEW)).toBe(true)
  })

  it('is case-insensitive', () => {
    expect(isEmbeddedBrowserUA('some app INSTAGRAM/1.0')).toBe(true)
  })
})
