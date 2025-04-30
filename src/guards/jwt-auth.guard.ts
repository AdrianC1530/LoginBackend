// src/auth/guards/jwt-auth.guard.ts
import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor() {
    super();
  }

  canActivate(context: ExecutionContext) {
    // Heredamos el comportamiento básico desde AuthGuard
    return super.canActivate(context);
  }

  handleRequest(err, user, info) {
    // Manejo de errores personalizado
    if (err || !user) {
      throw err || new UnauthorizedException('Authentication token is missing or invalid');
    }
    return user;
  }
}