import { describe, expect, it } from 'vitest';
import { REMOTE_SCRIPT_URLS, stripRemoteScriptUrls } from '../build/strip-remote-scripts';

// Shapes copied from the Firebase SDK bundle (trusted-types allow-list and the reCAPTCHA loaders).
const SDK = [
  'var Wi=[`https://www.googletagmanager.com/gtag/js`,`https://apis.google.com/js/api.js`,`https://www.google.com/recaptcha/api.js`,`https://www.google.com/recaptcha/enterprise.js`];',
  'var Za=`https://www.google.com/recaptcha/api.js`;',
  'Yi(t,`https://www.google.com/recaptcha/enterprise.js?render=explicit`),t.onload=e;',
  'const other="https://firebasevertexai.googleapis.com/v1beta";',
].join('\n');

describe('stripRemoteScriptUrls()', () => {
  it('removes every remote script URL the MV3 extension can never load', () => {
    const out = stripRemoteScriptUrls(SDK);
    for (const u of REMOTE_SCRIPT_URLS) expect(out).not.toContain(u);
    expect(out).not.toMatch(/recaptcha|gtag\/js|apis\.google\.com\/js/);
  });

  it('keeps API endpoints and never turns an allow-list entry into an empty string', () => {
    const out = stripRemoteScriptUrls(SDK);
    expect(out).toContain('https://firebasevertexai.googleapis.com/v1beta');
    expect(out).not.toContain('``');
    expect(out).toContain('about:invalid#remote-script-removed');
  });
});
