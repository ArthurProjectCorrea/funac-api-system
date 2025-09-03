import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma.service';
import { TokenBlacklistService } from '../services/token-blacklist.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
    private tokenBlacklistService: TokenBlacklistService,
  ) {
    const jwtSecret = configService.get<string>('JWT_SECRET');
    if (!jwtSecret) {
      throw new Error('JWT_SECRET não configurado');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
      passReqToCallback: true, // Necessário para acessar o token raw
    });
  }

  async validate(
    req: any,
    payload: {
      sub: string;
      jti?: string; // Token ID para blacklist
      roles?: string[];
      permissions?: string[];
      exp?: number;
    },
  ) {
    // Verificar se o token está na blacklist
    if (payload.jti) {
      const isBlacklisted = await this.tokenBlacklistService.isTokenBlacklisted(
        payload.jti,
      );
      if (isBlacklisted) {
        throw new UnauthorizedException('Token revogado');
      }
    }

    // Verificar se usuário ainda existe e está ativo
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        status: true,
        mfaEnabled: true,
        lastLoginAt: true,
      },
    });

    if (!user || user.status !== 'ACTIVE') {
      throw new UnauthorizedException('Usuário não encontrado ou inativo');
    }

    // Verificação adicional: se o token foi emitido antes do último login forçado
    // (útil para invalidar tokens após mudança de senha)
    if (payload.exp && user.lastLoginAt) {
      const tokenIssuedAt = payload.exp - 15 * 60; // Assumindo 15 min de validade
      const lastLoginTimestamp = Math.floor(user.lastLoginAt.getTime() / 1000);

      if (tokenIssuedAt < lastLoginTimestamp) {
        throw new UnauthorizedException(
          'Token emitido antes da última autenticação válida',
        );
      }
    }

    return {
      userId: user.id,
      email: user.email,
      status: user.status,
      mfaEnabled: user.mfaEnabled,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      tokenId: payload.jti,
    };
  }
}
