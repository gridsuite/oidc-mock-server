/* eslint-disable no-console */

const assert = require('assert');
const camelCase = require('camelcase');
const Provider = require('oidc-provider');
const Koa = require('koa');
const mount = require('koa-mount');

const port = process.env.PORT || 3000;

const clientCount = Number(process.env.CLIENT_COUNT || 1);

const clientNums = Array.from({ length: clientCount }, (_, i) => i + 1);

const clientConfigs = clientNums.map(clientNum => {
  const suffix = clientNum > 1 ? `_${clientNum}` : '';

  const clientConfig = ['CLIENT_ID', 'CLIENT_REDIRECT_URI', 'CLIENT_LOGOUT_REDIRECT_URI'].reduce((acc, v) => {
    const v2 = `${v}${suffix}`;
    assert(process.env[v2], `${v2} config missing`);
    acc[camelCase(v)] = process.env[v2];
    return acc;
  }, {});

  if (process.env[`CLIENT_SILENT_REDIRECT_URI${suffix}`]) {
    clientConfig.clientSilentRedirectUri = process.env[`CLIENT_SILENT_REDIRECT_URI${suffix}`];
  }

  clientConfig.redirect_uris = [clientConfig.clientRedirectUri,
    clientConfig.clientSilentRedirectUri].filter(Boolean);

  return clientConfig;
});

// TODO could be refactored to ISSUER_BASEURL with http://localhost directly
// Or we could allow to set koa app proxy = true to autodetect these from the x-forwarded-* headers:
// https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#trusting-tls-offloading-proxies
const proto = process.env.ISSUER_PROTO || 'http://';
const host = process.env.ISSUER_HOST || 'localhost';
const prefix = process.env.ISSUER_PREFIX || '/';
const domain = process.env.EMAIL_DOMAIN || '@domain.com';

const oidcConfig = {
  async findAccount(ctx, id) {
    return {
      accountId: id,
      async claims() { return { sub: id, name: id, email: id + domain }; },
    };
  },
  claims: {
    openid: [
      'sub', 'name', 'email'
    ],
  },
  clients: clientConfigs.map(clientConfig => ({
    client_id: clientConfig.clientId,
    redirect_uris: clientConfig.redirect_uris,
    pkce: {
      required: true,
    },
    token_endpoint_auth_method: 'none',
    post_logout_redirect_uris: [clientConfig.clientLogoutRedirectUri]
  }))
};

const oidc = new Provider(`${proto}${host}${prefix}`, oidcConfig);

const { invalidate: orig } = oidc.Client.Schema.prototype;

oidc.Client.Schema.prototype.invalidate = function invalidate(message, code) {
  if (code === 'implicit-force-https' || code === 'implicit-forbid-localhost') {
    return;
  }

  orig.call(this, message);
};

const app = new Koa();
app.use(mount(prefix, oidc.app));

// TODO can this be always enabled? It is necessary for https but not necessary for http
// because the server generates urls in openid-configuration from ctx.href
if (proto === 'https://') {
  app.proxy = true;
}

app.listen(port);
