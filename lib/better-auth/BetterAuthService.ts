import type { AsenaAuthProvider, AuthSession, AuthUser } from '@asenajs/asena/auth';
import { defaultRolesResolver } from '../helpers/roles';
import type { BetterAuthInstance, BetterAuthOptions } from '../types';

/**
 * Better Auth behind the `@asenajs/asena/auth` contract. Extend it and decorate the subclass with
 * `@BetterAuth({ auth })`. Header tokens need Better Auth's `bearer` plugin.
 */
export abstract class BetterAuthService<TUser extends AuthUser = AuthUser> implements AsenaAuthProvider<TUser> {
  protected options: BetterAuthOptions<TUser> | null = null;

  private readonly setCookies = new WeakMap<Request, string[]>();

  public get primary(): boolean {
    return this.getOptions().primary === true;
  }

  public get instance(): BetterAuthInstance {
    return this.getOptions().auth;
  }

  public async getSession(request: Request): Promise<AuthSession<TUser> | null> {
    const { headers, response } = await this.instance.api.getSession({ headers: request.headers, returnHeaders: true });
    const cookies = headers.getSetCookie();

    if (cookies.length > 0) {
      this.setCookies.set(request, cookies);
    }

    const session = response?.session;

    if (!response || !session?.id || !session.userId) {
      return null;
    }

    return {
      user: { ...response.user },
      session: {
        id: session.id,
        userId: session.userId,
        createdAt: new Date(session.createdAt),
        expiresAt: new Date(session.expiresAt),
      },
    };
  }

  /**
   * The `Set-Cookie` values Better Auth answered `getSession(request)` with (e.g. a session refresh); else `[]`.
   * @internal
   */
  public responseCookies(request: Request): string[] {
    return this.setCookies.get(request) ?? [];
  }

  public getRoles(session: AuthSession<TUser>): string[] {
    const resolver = this.getOptions().roles;

    return resolver ? resolver(session) : defaultRolesResolver(session);
  }

  protected setBetterAuth(options: BetterAuthOptions<TUser>): void {
    const auth = options?.auth as Partial<BetterAuthInstance> | undefined;

    if (typeof auth?.handler !== 'function' || typeof auth.api?.getSession !== 'function') {
      throw new Error(
        `${this.constructor.name}: @BetterAuth needs a Better Auth instance as \`auth\` ` +
          '(an object with handler(request) and api.getSession({ headers })), e.g. auth: betterAuth({...}).',
      );
    }

    this.options = options;
  }

  private getOptions(): BetterAuthOptions<TUser> {
    if (!this.options) {
      throw new Error(
        `${this.constructor.name}: Better Auth not initialized. Decorate the class with @BetterAuth({ auth }).`,
      );
    }

    return this.options;
  }
}
