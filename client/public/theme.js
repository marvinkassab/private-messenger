/* Applies the saved theme before the page paints, so a dark-mode user never
   sees a white flash on load.
 *
 * This is a separate file rather than an inline script because the site's
 * Content Security Policy forbids inline scripts. As an inline block it was
 * silently refused in production, which meant the flash it exists to prevent
 * happened on every load, and every load logged a policy violation. Keeping
 * it external needs no hash in the policy to drift out of date.
 *
 * It must stay synchronous and in <head>: deferring it would let the wrong
 * theme paint first, which is the entire problem. */
try {
  var t = localStorage.getItem("pm.theme");
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
} catch (e) {
  /* storage blocked: fall back to the media query in the stylesheet */
}
