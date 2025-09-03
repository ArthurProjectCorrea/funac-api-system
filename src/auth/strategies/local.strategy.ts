import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { AuthService, LoginResult } from '../services/auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true,
    });
  }

  async validate(
    req: Request,
    email: string,
    password: string,
  ): Promise<LoginResult> {
    const ipAddress = req.ip || req.connection?.remoteAddress || 'unknown';
    const userAgent = req.get?.('User-Agent') || 'unknown';

    try {
      const result = await this.authService.login({
        email,
        password,
        ipAddress,
        userAgent,
      });

      return result;
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Erro desconhecido';
      throw new UnauthorizedException(message);
    }
  }
}
