import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma.service';
import { TokenType } from '@prisma/client';
import * as crypto from 'crypto';

export interface TokenPayload {
  userId?: string;
  email?: string;
  type: TokenType;
  data?: Record<string, any>;
}

@Injectable()
export class TokenService {
  private readonly emailVerifyExpiration: number;
  private readonly passwordResetExpiration: number;
  private readonly invitationExpiration: number;

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {
    this.emailVerifyExpiration = this.configService.get<number>(
      'EMAIL_VERIFY_EXPIRATION_MINUTES',
      60,
    );
    this.passwordResetExpiration = this.configService.get<number>(
      'PASSWORD_RESET_EXPIRATION_MINUTES',
      20,
    );
    this.invitationExpiration = this.configService.get<number>(
      'INVITATION_EXPIRATION_DAYS',
      7,
    );
  }

  /**
   * Gera um token seguro para verificação de e-mail
   */
  async generateEmailVerificationToken(userId: string): Promise<string> {
    const token = this.generateSecureToken();
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + this.emailVerifyExpiration);

    await this.prisma.token.create({
      data: {
        userId,
        type: TokenType.EMAIL_VERIFICATION,
        tokenHash,
        expiresAt,
      },
    });

    return token;
  }

  /**
   * Gera um token para reset de senha
   */
  async generatePasswordResetToken(userId: string): Promise<string> {
    // Invalidar tokens de reset existentes
    await this.invalidateTokensByType(userId, TokenType.PASSWORD_RESET);

    const token = this.generateSecureToken();
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + this.passwordResetExpiration);

    await this.prisma.token.create({
      data: {
        userId,
        type: TokenType.PASSWORD_RESET,
        tokenHash,
        expiresAt,
      },
    });

    return token;
  }

  /**
   * Gera um token de convite
   */
  async generateInvitationToken(
    email: string,
    data: Record<string, any> = {},
  ): Promise<string> {
    const token = this.generateSecureToken();
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.invitationExpiration);

    await this.prisma.token.create({
      data: {
        type: TokenType.INVITATION,
        tokenHash,
        expiresAt,
        data: {
          email,
          ...data,
        },
      },
    });

    return token;
  }

  /**
   * Valida e consome um token
   */
  async validateAndConsumeToken(
    token: string,
    type: TokenType,
  ): Promise<{
    isValid: boolean;
    userId?: string;
    data?: Record<string, any>;
    error?: string;
  }> {
    const tokenHash = this.hashToken(token);

    const tokenRecord = await this.prisma.token.findFirst({
      where: {
        tokenHash,
        type,
        usedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!tokenRecord) {
      return {
        isValid: false,
        error: 'Token inválido ou expirado',
      };
    }

    // Marcar token como usado
    await this.prisma.token.update({
      where: { id: tokenRecord.id },
      data: { usedAt: new Date() },
    });

    return {
      isValid: true,
      userId: tokenRecord.userId || undefined,
      data: (tokenRecord.data as Record<string, any>) || undefined,
    };
  }

  /**
   * Valida token sem consumi-lo (para verificação prévia)
   */
  async validateToken(
    token: string,
    type: TokenType,
  ): Promise<{
    isValid: boolean;
    userId?: string;
    data?: Record<string, any>;
    error?: string;
  }> {
    const tokenHash = this.hashToken(token);

    const tokenRecord = await this.prisma.token.findFirst({
      where: {
        tokenHash,
        type,
        usedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!tokenRecord) {
      return {
        isValid: false,
        error: 'Token inválido ou expirado',
      };
    }

    return {
      isValid: true,
      userId: tokenRecord.userId || undefined,
      data: (tokenRecord.data as Record<string, any>) || undefined,
    };
  }

  /**
   * Invalida todos os tokens de um tipo para um usuário
   */
  async invalidateTokensByType(userId: string, type: TokenType): Promise<void> {
    await this.prisma.token.updateMany({
      where: {
        userId,
        type,
        usedAt: null,
      },
      data: {
        usedAt: new Date(),
      },
    });
  }

  /**
   * Invalida todos os tokens de um usuário
   */
  async invalidateAllUserTokens(userId: string): Promise<void> {
    await this.prisma.token.updateMany({
      where: {
        userId,
        usedAt: null,
      },
      data: {
        usedAt: new Date(),
      },
    });
  }

  /**
   * Limpa tokens expirados (para ser executado periodicamente)
   */
  async cleanupExpiredTokens(): Promise<number> {
    const result = await this.prisma.token.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    });

    return result.count;
  }

  /**
   * Cria um token genérico
   */
  async createToken(
    userId: string,
    type: TokenType,
    data: Record<string, any> = {},
  ): Promise<string> {
    const token = this.generateSecureToken();
    const tokenHash = this.hashToken(token);

    const expiresAt = new Date();

    switch (type) {
      case TokenType.EMAIL_VERIFICATION:
        expiresAt.setMinutes(
          expiresAt.getMinutes() + this.emailVerifyExpiration,
        );
        break;
      case TokenType.PASSWORD_RESET:
        expiresAt.setMinutes(
          expiresAt.getMinutes() + this.passwordResetExpiration,
        );
        break;
      case TokenType.INVITATION:
        expiresAt.setDate(expiresAt.getDate() + this.invitationExpiration);
        break;
      default:
        expiresAt.setHours(expiresAt.getHours() + 1); // 1 hora por padrão
    }

    await this.prisma.token.create({
      data: {
        userId,
        type,
        tokenHash,
        expiresAt,
        data,
      },
    });

    return token;
  }

  /**
   * Gera token criptograficamente seguro
   */
  private generateSecureToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Gera hash do token para armazenamento
   */
  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
