import { SetMetadata } from '@nestjs/common';
import * as KeycloakConnect from 'keycloak-connect';

export enum DecisionStrategy {
  Unanimous,
  Affirmative,
}

export type EnforcerOptionsWithDecision = KeycloakConnect.EnforcerOptions & {
  decisionStrategy?: DecisionStrategy;
};

export const META_ENFORCER_OPTIONS = 'enforcer-options';

/**
 * Keycloak enforcer options
 * @param opts - enforcer options
 * @since 1.3.0
 */
export const EnforcerOptions = (opts: EnforcerOptionsWithDecision) =>
  SetMetadata(META_ENFORCER_OPTIONS, opts);
