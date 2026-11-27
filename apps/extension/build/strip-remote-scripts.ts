/**
 * The Firebase SDK carries the URLs of remote scripts it can load on a web page (reCAPTCHA for
 * App Check, gapi and gtag). A Manifest V3 extension may not load remote code and never uses
 * them (App Check runs on the debug token there), so the extension build replaces the URLs with
 * an inert value. Not an empty string: the SDK's trusted-types allow-list checks
 * `url.startsWith(entry)`, and an empty entry would match every URL.
 */
import type { Plugin } from 'vite';

export const REMOTE_SCRIPT_URLS = [
  'https://www.google.com/recaptcha/enterprise.js?render=explicit',
  'https://www.google.com/recaptcha/enterprise.js',
  'https://www.google.com/recaptcha/api.js',
  'https://apis.google.com/js/api.js',
  'https://www.googletagmanager.com/gtag/js',
] as const;

const INERT = 'about:invalid#remote-script-removed';

export function stripRemoteScriptUrls(code: string): string {
  let out = code;
  // Longest first, so "enterprise.js?render=explicit" is not left with a dangling query.
  for (const url of REMOTE_SCRIPT_URLS) out = out.split(url).join(INERT);
  return out;
}

export function stripRemoteScripts(): Plugin {
  return {
    name: 'scam-shield:strip-remote-scripts',
    apply: 'build',
    renderChunk(code) {
      const out = stripRemoteScriptUrls(code);
      return out === code ? null : { code: out, map: null };
    },
  };
}
