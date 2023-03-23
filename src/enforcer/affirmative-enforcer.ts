// eslint-disable-next-line @typescript-eslint/no-var-requires
const Enforcer = require('keycloak-connect/middleware');
import { DecisionStrategy } from '../decorators/enforcer-options.decorator';

function handlePermissions(permissions, callback) {
  for (let i = 0; i < permissions.length; i++) {
    const expected = permissions[i].split(':');
    const resource = expected[0];
    let scope;

    if (expected.length > 1) {
      scope = expected[1];
    }

    const r = callback(resource, scope);

    if (r === false || r === true) {
      return r;
    }
  }

  return true;
}

export class AffirmativeEnforcer extends Enforcer {
  protected decisionStrategy: DecisionStrategy;

  constructor(keycloak, config) {
    super(keycloak, config);
    this.decisionStrategy =
      config.decisionStrategy ?? DecisionStrategy.Affirmative;
  }

  enforce(expectedPermissions) {
    const keycloak = this.keycloak;
    const config = this.config;
    const decisionStategy = this.decisionStrategy;

    if (typeof expectedPermissions === 'string') {
      expectedPermissions = [expectedPermissions];
    }

    return function(request, response, next) {
      if (!expectedPermissions || expectedPermissions.length === 0) {
        return next();
      }

      const authzRequest: any = {
        audience: config.resource_server_id,
        response_mode: config.response_mode,
      };

      handlePermissions(expectedPermissions, function(resource, scope) {
        if (!authzRequest.permissions) {
          authzRequest.permissions = [];
        }

        const permission: any = { id: resource };

        if (scope) {
          permission.scopes = [scope];
        }

        authzRequest.permissions.push(permission);
      });

      if (request.kauth && request.kauth.grant) {
        if (
          handlePermissions(expectedPermissions, function(resource, scope) {
            if (
              !request.kauth.grant.access_token.hasPermission(resource, scope)
            ) {
              return false;
            }
          })
        ) {
          return next();
        }
      }

      if (config.claims) {
        const claims = config.claims(request);

        if (claims) {
          authzRequest.claim_token = Buffer.from(
            JSON.stringify(claims),
          ).toString('base64');
          authzRequest.claim_token_format =
            'urn:ietf:params:oauth:token-type:jwt';
        }
      }
      if (config.response_mode === 'permissions') {
        return keycloak
          .checkPermissions(authzRequest, request, function(permissions) {
            if (
              handlePermissions(expectedPermissions, function(resource, scope) {
                if (!permissions || permissions.length === 0) {
                  return false;
                }

                for (let j = 0; j < permissions.length; j++) {
                  const permission = permissions[j];

                  if (
                    permission.rsid === resource ||
                    permission.rsname === resource
                  ) {
                    if (scope) {
                      if (permission.scopes && permission.scopes.length > 0) {
                        if (
                          decisionStategy === DecisionStrategy.Affirmative &&
                          permission.scopes.includes(scope)
                        ) {
                          return true;
                        }
                        if (
                          decisionStategy === DecisionStrategy.Unanimous &&
                          !permission.scopes.includes(scope)
                        ) {
                          return false;
                        }
                        break;
                      }
                      return false;
                    }
                  }
                }
              })
            ) {
              request.permissions = permissions;
              return next();
            }

            return keycloak.accessDenied(request, response, next);
          })
          .catch(function() {
            return keycloak.accessDenied(request, response, next);
          });
      } else if (config.response_mode === 'token') {
        authzRequest.response_mode = undefined;
        return keycloak
          .checkPermissions(authzRequest, request)
          .then(function(grant) {
            if (
              handlePermissions(expectedPermissions, function(resource, scope) {
                if (
                  decisionStategy === DecisionStrategy.Affirmative &&
                  grant.access_token.hasPermission(resource, scope)
                ) {
                  return true;
                }
                if (
                  decisionStategy === DecisionStrategy.Unanimous &&
                  !grant.access_token.hasPermission(resource, scope)
                ) {
                  return false;
                }
              })
            ) {
              return next();
            }

            return keycloak.accessDenied(request, response, next);
          })
          .catch(function() {
            return keycloak.accessDenied(request, response, next);
          });
      }
    };
  }
}
