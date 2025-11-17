import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';
import { Request } from 'express';

@Injectable()
export class RefreshJwtGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();

    const rawRefresh = req.body?.refreshToken;

    const token =
      typeof rawRefresh === 'string' ? rawRefresh : rawRefresh?.token;


    if (!token) {
      throw new UnauthorizedException('Refresh token відсутній');
    }
    try {
      const payload = this.authService.verifyToken(token);
      req['user'] = payload;
      return true;
    } catch {
      throw new UnauthorizedException(
        'Refresh token недійсний або прострочений',
      );
    }
  }
}
