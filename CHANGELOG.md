# @asenajs/asena-auth

## 1.0.2

### Patch Changes

- ca18a57: Widen the `typescript` peer range to accept TypeScript 6 and 7. The toolchain itself moves to TypeScript 7; the published output is unchanged.

## 1.0.1

### Patch Changes

- 0118ae1: Accept @asenajs/asena 0.13 as a peer.

## 1.0.0

### Major Changes

- ddb273a: `@asenajs/asena-auth` is the authentication package for AsenaJS. It implements the `@asenajs/asena/auth` contract with two providers: `AsenaAuthService` with `@Auth` (opaque session tokens stored only as hashes, carried as `Authorization: Bearer` or a cookie, sliding expiry, a pluggable `AuthSessionStore` with `MemoryAuthStore` built in, `Bun.password` hashing) and `BetterAuthService` with `@BetterAuth` and `BetterAuthController`, which mounts a Better Auth instance and forwards its refreshed session cookies. Several providers can live in one app; a route picks one with `@Protected({ provider })`, otherwise the provider marked `primary: true` (or the only one) serves it.

  `AuthGuard` enforces `@Protected`, `@Public` and `@Roles` by putting `AuthGuardMiddleware` in front of the route's own middlewares, its validator and its context contract, so an unauthenticated request is rejected before its body is read; global and controller middlewares run first. `AuthSessionMiddleware` resolves the session once per request without rejecting, and `AuthWebSocketMiddleware` rejects a WebSocket upgrade without a session (401) and accepts the browser token as `Sec-WebSocket-Protocol: bearer, <token>`. `authComponents` lists every shipped component for `imports: [...authComponents]`.

  Native sessions: `logout(ctx)`, `revokeSessionById(id)`, `listUserSessions(userId)` (stores may implement the optional `listByUser`), `rotateSession(ctx, user?)`, an absolute lifetime (`absoluteTtl`, 30 days by default) that sliding never extends, a cross-site check for cookie sessions (`csrf`, on by default; Bearer is exempt), and `loadUser` to read the current user on every request. A guard 401 carries `WWW-Authenticate: Bearer`, and a guard mark this version does not understand fails the boot instead of leaving the route open. `@asenajs/asena-auth/testing` provides `TestAuthProvider`, which takes the user from a request header.

  A misconfiguration fails the boot, not a request: a protected route whose provider is missing or ambiguous, more than one `primary: true` provider, and a registered session or WebSocket middleware that cannot pick a provider (several providers, none primary, no `providerName`) each fail the boot with a message naming the fix. Works with ergenecore and hono-adapter; requires Bun 1.4 and `@asenajs/asena` 0.12.2 or higher, and `better-auth` 1.2 or higher (below 2) only for the Better Auth provider.
