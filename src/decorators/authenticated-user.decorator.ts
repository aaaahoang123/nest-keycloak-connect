import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { extractRequest } from '../util';
import { KeycloakAuthenticateUser } from '../interface/keycloak-authenticate-user.interface';

/**
 * Retrieves the current Keycloak logged-in user.
 * @since 1.5.0
 */
export const AuthenticatedUser = createParamDecorator<
  any,
  ExecutionContext,
  KeycloakAuthenticateUser
>(
  (data: unknown, ctx: ExecutionContext): KeycloakAuthenticateUser => {
    const [req] = extractRequest(ctx);
    return req.user;
  },
);
