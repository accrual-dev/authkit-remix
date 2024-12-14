import { HandleAuthOptions } from './interfaces.js';
import { WORKOS_CLIENT_ID } from './env-variables.js';
import { workos } from './workos.js';
import { encryptSession } from './session.js';
import { getSession, commitSession, cookieName } from './cookie.js';
import { redirect, json, LoaderFunctionArgs } from '@remix-run/node';

export function authLoader(options: HandleAuthOptions = {}) {
  return async function loader({ request }: LoaderFunctionArgs) {
    const { returnPathname: defaultReturnPathname = '/', onSuccess } = options;
    let url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    // Decode returnPathname if state is provided
    let returnPathname: string | null = null;
    if (state && state !== 'null') {
      const decoded = JSON.parse(atob(state));
      returnPathname = decoded.returnPathname ?? null;
    }

    // If no code is found, we cannot proceed
    if (!code) {
      return errorResponse();
    }

    try {
      const { accessToken, refreshToken, user, impersonator, oauthTokens } =
        await workos.userManagement.authenticateWithCode({
          clientId: WORKOS_CLIENT_ID,
          code,
        });

      // Clean up used search parameters
      url.searchParams.delete('code');
      url.searchParams.delete('state');

      // Determine the final redirect URL
      const finalRedirect = returnPathname ?? defaultReturnPathname;

      if (!finalRedirect.startsWith('/')) {
        // full URL
        url = new URL(finalRedirect);
      } else {
        // relative path
        const potentialUrl = new URL(finalRedirect, url.origin);

        // If the relative path includes additional query params, merge them in
        url.pathname = potentialUrl.pathname;
        for (const [key, value] of potentialUrl.searchParams) {
          url.searchParams.append(key, value);
        }
      }

      // Encrypt and store the session
      const encryptedSession = await encryptSession({
        accessToken,
        refreshToken,
        user,
        impersonator,
        headers: {},
      });

      const session = await getSession(cookieName);
      session.set('jwt', encryptedSession);
      const cookie = await commitSession(session);

      // Optional success callback
      if (onSuccess) {
        await onSuccess({
          accessToken,
          impersonator: impersonator ?? null,
          oauthTokens: oauthTokens ?? null,
          refreshToken,
          user,
        });
      }

      return redirect(url.toString(), {
        headers: {
          'Set-Cookie': cookie,
        },
      });
    } catch (error) {
      console.error({
        error: error instanceof Error ? error.message : String(error),
      });
      return errorResponse();
    }

    function errorResponse() {
      return json(
        {
          error: {
            message: 'Something went wrong',
            description: 'Couldn’t sign in. If you are not sure what happened, please contact your organization admin.',
          },
        },
        { status: 500 },
      );
    }
  };
}
