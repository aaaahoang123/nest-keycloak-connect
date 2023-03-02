import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { KeycloakPermission } from '../interface/keycloak-permission.interface';

export const Permissions = createParamDecorator<
  any,
  ExecutionContext,
  KeycloakPermission[]
>((data, ctx: ExecutionContext): KeycloakPermission[] => {
  const req = ctx.switchToHttp().getRequest();
  return req.permissions;
});
