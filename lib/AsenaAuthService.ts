import type { AsenaContext } from '@asenajs/asena/adapter';
import { OnStart, OnStop } from '@asenajs/asena/decorators/ioc';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession, AuthUser } from '@asenajs/asena/auth';
import { generateToken, hashPassword, hashToken, verifyPassword } from './crypto';
import { applySessionCookie, clearSessionCookie, getRawRequest } from './helpers/context';
import { defaultRolesResolver } from './helpers/roles';
import type { AuthSessionStore, StoredSession } from './store';
import type { AuthOptions } from './types';

const DEFAULT_TTL_SECONDS = 604_800;
const DEFAULT_ABSOLUTE_TTL_SECONDS = 2_592_000;
const DEFAULT_COOKIE_NAME = 'asena_session';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Providers may share one store object; it starts with the first and stops with the last.
const storeUsers = new WeakMap<AuthSessionStore<any>, { users: number; started: Promise<void> }>();

export interface SessionCookieOptions {
  httpOnly: true;
  sameSite: 'strict' | 'lax' | 'none';
  secure: boolean;
  path: string;
  domain?: string;
  maxAge: number;
}

/**
 * Native opaque-session provider. Extend it and decorate the subclass with `@Auth(...)`.
 * Tokens travel as `Authorization: Bearer` (wins) or the session cookie; only their SHA-256 is stored.
 */
export abstract class AsenaAuthService<TUser extends AuthUser = AuthUser> implements AsenaAuthProvider<TUser> {
  protected options: AuthOptions<TUser> | null = null;

  protected store: AuthSessionStore<TUser> | null = null;

  private startedStore: AuthSessionStore<TUser> | null = null;

  private readonly slidCookies = new WeakMap<Request, { token: string; maxAge: number }>();

  @OnStart()
  public async onStart(): Promise<void> {
    if (!this.options || !this.store) {
      throw new Error(
        `${this.constructor.name}: auth options not initialized. Decorate the class with @Auth({...}) and extend AsenaAuthService.`,
      );
    }

    const absoluteTtl = this.options.absoluteTtl ?? DEFAULT_ABSOLUTE_TTL_SECONDS;

    if (absoluteTtl !== false && absoluteTtl < this.ttlSeconds) {
      throw new Error(
        `${this.constructor.name}: absoluteTtl (${absoluteTtl}) is smaller than sessionTtl (${this.ttlSeconds}). ` +
          'Raise absoluteTtl, lower sessionTtl, or set absoluteTtl: false.',
      );
    }

    if (this.startedStore) {
      return;
    }

    const store = this.store;
    let entry = storeUsers.get(store);

    if (!entry) {
      entry = { users: 0, started: (async () => store.onStart?.())() };
      storeUsers.set(store, entry);
    }

    entry.users++;
    this.startedStore = store;

    try {
      await entry.started;
    } catch (error) {
      this.startedStore = null;

      if (--entry.users === 0 && storeUsers.get(store) === entry) {
        storeUsers.delete(store);
      }

      throw error;
    }
  }

  @OnStop()
  public async onStop(): Promise<void> {
    const store = this.startedStore;
    const entry = store && storeUsers.get(store);

    this.startedStore = null;

    if (!store || !entry || --entry.users > 0) {
      return;
    }

    storeUsers.delete(store);
    await entry.started;
    await store.onStop?.();
  }

  public get primary(): boolean {
    return this.getOptions().primary === true;
  }

  public get cookieName(): string {
    return this.getOptions().cookie?.name ?? DEFAULT_COOKIE_NAME;
  }

  public get cookieOptions(): SessionCookieOptions {
    const cookie = this.getOptions().cookie ?? {};
    const options: SessionCookieOptions = {
      httpOnly: true,
      sameSite: cookie.sameSite ?? 'lax',
      secure: cookie.secure ?? true,
      path: cookie.path ?? '/',
      maxAge: this.ttlSeconds,
    };

    if (cookie.domain !== undefined) {
      options.domain = cookie.domain;
    }

    return options;
  }

  public async createSession(user: TUser): Promise<{ token: string; session: AuthSession<TUser> }> {
    const token = generateToken(this.getOptions().tokenBytes ?? 32);
    const now = Date.now();
    const stored: StoredSession<TUser> = {
      id: hashToken(token),
      userId: user.id,
      user: this.snapshot(user),
      createdAt: now,
      expiresAt: now + this.ttlSeconds * 1000,
    };

    await this.getStore().create(stored);

    return { token, session: this.toAuthSession(stored) };
  }

  public async getSession(request: Request): Promise<AuthSession<TUser> | null> {
    return (await this.resolveStored(request))?.session ?? null;
  }

  /**
   * Re-issues, once, the cookie of a session `getSession` slid for this request, its `Max-Age` capped at the
   * session's remaining lifetime. Called after the handler, so a cookie the handler writes or clears wins.
   * @internal
   */
  public async flushSlidCookie(ctx: AsenaContext<any, any>): Promise<void> {
    const request = getRawRequest(ctx);
    const slid = this.slidCookies.get(request);

    if (!slid) {
      return;
    }

    this.slidCookies.delete(request);
    await ctx.setCookie(this.cookieName, slid.token, { extraOptions: { ...this.cookieOptions, maxAge: slid.maxAge } });
  }

  /** @internal */
  public discardSlidCookie(ctx: AsenaContext<any, any>): void {
    this.slidCookies.delete(getRawRequest(ctx));
  }

  public getRoles(session: AuthSession<TUser>): string[] {
    const resolver = this.getOptions().roles;

    return resolver ? resolver(session) : defaultRolesResolver(session);
  }

  public async revokeSession(token: string): Promise<void> {
    await this.getStore().delete(hashToken(token));
  }

  /** Deletes by the stored id (`AuthSession.session.id`), e.g. to sign out one of a user's devices. */
  public async revokeSessionById(id: string): Promise<void> {
    await this.getStore().delete(id);
  }

  /**
   * Ends the session of the current request (the Bearer token, else the cookie, as `getSession` reads them)
   * and clears the session cookie. Without a session it only clears the cookie. With a Bearer token, a different
   * session in the cookie is not revoked; its row expires on its own. A cross-site request (see `csrf`) does not
   * read the cookie, so it cannot end that session - by design, the cookie is still cleared.
   */
  public async logout(ctx: AsenaContext<any, any>): Promise<void> {
    const request = getRawRequest(ctx);
    const read = this.readToken(request);

    this.slidCookies.delete(request);

    if (read) {
      await this.revokeSession(read.token);
    }

    await clearSessionCookie(ctx, this);
  }

  /**
   * Replaces the request's session (e.g. after a privilege change) and returns the new token; the cookie is
   * re-issued when the old token came from it. Rotation is a fresh authentication: `createdAt` is now, so
   * `absoluteTtl` restarts. Without `user` the new session stores the current one's stored user (not the
   * `loadUser` result). The old session ends only once the new one exists, and `getAuthSession(ctx)` returns the
   * new one for the rest of the request. Throws when the request has no session.
   */
  public async rotateSession(ctx: AsenaContext<any, any>, user?: TUser): Promise<string> {
    const request = getRawRequest(ctx);
    const read = this.readToken(request);
    const current = read && (await this.resolveStored(request));

    if (!current) {
      throw new Error(`${this.constructor.name}.rotateSession: the request has no session to rotate.`);
    }

    const { token, session } = await this.createSession(user ?? current.stored.user);

    await this.revokeSessionById(current.stored.id);
    this.slidCookies.delete(request);
    ctx.setValue(AUTH_SESSION_CONTEXT_KEY, user ? session : { ...session, user: current.session.user });

    if (read.fromCookie) {
      await applySessionCookie(ctx, this, token);
    }

    return token;
  }

  /**
   * The user's unexpired sessions, each with the user stored at `createSession` (`loadUser` is not called).
   * Needs a store implementing `listByUser`.
   */
  public async listUserSessions(userId: string): Promise<AuthSession<TUser>[]> {
    const store = this.getStore();

    if (!store.listByUser) {
      throw new Error(
        `${this.constructor.name}.listUserSessions: the session store ${store.constructor.name} does not implement listByUser(userId).`,
      );
    }

    const now = Date.now();
    const rows = await store.listByUser(userId);

    return rows.filter((row) => this.isLive(row, now)).map((row) => this.toAuthSession(row));
  }

  public async revokeUserSessions(userId: string): Promise<void> {
    await this.getStore().deleteByUser(userId);
  }

  public async hashPassword(password: string): Promise<string> {
    return hashPassword(password, this.getOptions().hashing);
  }

  public async verifyPassword(password: string, hash: string): Promise<boolean> {
    return verifyPassword(password, hash);
  }

  protected setAuthOptions(options: AuthOptions<TUser>): void {
    this.options = options;
  }

  protected setStore(store: AuthSessionStore<TUser>): void {
    this.store = store;
  }

  private get ttlSeconds(): number {
    return this.getOptions().sessionTtl ?? DEFAULT_TTL_SECONDS;
  }

  private async resolveStored(
    request: Request,
  ): Promise<{ stored: StoredSession<TUser>; session: AuthSession<TUser> } | null> {
    const read = this.readToken(request);

    if (!read) {
      return null;
    }

    const { token, fromCookie } = read;
    const store = this.getStore();
    const stored = await store.get(hashToken(token));
    const now = Date.now();

    if (!stored || !this.isLive(stored, now)) {
      return null;
    }

    const loadUser = this.getOptions().loadUser;
    const loaded = loadUser ? await loadUser(stored.userId) : undefined;

    if (loadUser && (loaded === null || loaded === undefined)) {
      await store.delete(stored.id);

      return null;
    }

    const ttlMs = this.ttlSeconds * 1000;
    const expiresAt = Math.min(now + ttlMs, this.absoluteEnd(stored));

    if (this.getOptions().sliding !== false && stored.expiresAt - now < ttlMs / 2 && expiresAt > stored.expiresAt) {
      await store.touch(stored.id, expiresAt);

      if (fromCookie) {
        this.slidCookies.set(request, { token, maxAge: Math.floor((expiresAt - now) / 1000) });
      }

      return { stored, session: this.toAuthSession({ ...stored, expiresAt }, loaded) };
    }

    return { stored, session: this.toAuthSession(stored, loaded) };
  }

  private absoluteEnd(stored: StoredSession<TUser>): number {
    const absoluteTtl = this.getOptions().absoluteTtl ?? DEFAULT_ABSOLUTE_TTL_SECONDS;

    return absoluteTtl === false ? Infinity : stored.createdAt + absoluteTtl * 1000;
  }

  private isLive(stored: StoredSession<TUser>, now: number): boolean {
    return stored.expiresAt > now && this.absoluteEnd(stored) > now;
  }

  private readToken(request: Request): { token: string; fromCookie: boolean } | null {
    const bearer = this.readBearer(request);

    if (bearer) {
      return { token: bearer, fromCookie: false };
    }

    const cookie = this.readCookie(request.headers.get('cookie'));

    return cookie && !this.isCrossSite(request) ? { token: cookie, fromCookie: true } : null;
  }

  private isCrossSite(request: Request): boolean {
    const csrf = this.getOptions().csrf;
    const upgrade = request.headers.get('upgrade')?.toLowerCase() === 'websocket';

    if (csrf === false || (SAFE_METHODS.has(request.method) && !upgrade)) {
      return false;
    }

    const origin = request.headers.get('origin');

    if (origin !== null && csrf?.trustedOrigins?.includes(origin)) {
      return false;
    }

    const site = request.headers.get('sec-fetch-site');

    if (site !== null) {
      return site !== 'same-origin' && site !== 'none';
    }

    return origin !== null && origin !== new URL(request.url).origin;
  }

  private readBearer(request: Request): string | null {
    if (this.getOptions().bearer === false) {
      return null;
    }

    return /^bearer\s+(\S+)\s*$/i.exec(request.headers.get('authorization') ?? '')?.[1] ?? null;
  }

  private readCookie(header: string | null): string | null {
    if (!header) {
      return null;
    }

    const prefix = `${this.cookieName}=`;

    for (const part of header.split(';')) {
      const pair = part.trim();

      if (pair.startsWith(prefix)) {
        return pair.slice(prefix.length) || null;
      }
    }

    return null;
  }

  private snapshot(user: TUser): TUser {
    try {
      return structuredClone(user);
    } catch (cause) {
      throw new TypeError(
        `${this.constructor.name}.createSession: the user must be plain data (structuredClone failed; ` +
          'functions and symbols cannot be stored, class instances lose their prototype).',
        { cause },
      );
    }
  }

  private toAuthSession(stored: StoredSession<TUser>, loaded?: TUser | null): AuthSession<TUser> {
    return {
      user: loaded ?? structuredClone(stored.user),
      session: {
        id: stored.id,
        userId: stored.userId,
        createdAt: new Date(stored.createdAt),
        expiresAt: new Date(stored.expiresAt),
      },
    };
  }

  private getOptions(): AuthOptions<TUser> {
    if (!this.options) {
      throw new Error(`${this.constructor.name}: auth options not initialized. Decorate the class with @Auth({...}).`);
    }

    return this.options;
  }

  private getStore(): AuthSessionStore<TUser> {
    if (!this.store) {
      throw new Error(`${this.constructor.name}: no session store. Decorate the class with @Auth({...}).`);
    }

    return this.store;
  }
}
