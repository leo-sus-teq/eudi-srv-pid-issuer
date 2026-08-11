// Detects being shown inside the demo dashboard's iframe (see
// ../../../../../dashboard/) and flags <html> so main.css can hide this
// app's own header (see html.is-embedded rules there) - not a query param
// the framer has to remember, any framing triggers it, which is fine here
// since nothing else legitimately frames this app.
//
// An external file, not an inline <script> in the page itself: this app's
// CSP is `script-src 'self'` with no `'unsafe-inline'` (see
// ConfigureSecurity.kt), so an inline script here would just get silently
// blocked - same-origin external files are exactly what that policy is
// designed to still allow.
if (window.self !== window.top) {
    document.documentElement.classList.add("is-embedded");
}
