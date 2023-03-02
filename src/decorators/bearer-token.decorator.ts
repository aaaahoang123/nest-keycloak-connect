import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const BearerToken = createParamDecorator(
  (data, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest();
    const auth = req.headers.Authorization ?? req.headers.authorization;
    return auth?.replace('Bearer ', '') || undefined;
  },
);
