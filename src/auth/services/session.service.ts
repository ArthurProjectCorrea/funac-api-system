import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma.service';
import * as crypto from 'crypto';

export interface SessionData {
  userId: string;
  deviceFingerprint?: string;
  ipAddress?: string;
  userAgent?: string;
  riskScore?: number;
}

export interface RefreshTokenData {
  sessionId: string;
  userId: string;
  deviceFingerprint?: string;
}

@Injectable()
export class SessionService {
  private readonly refreshTokenExpiration: number;
  private readonly sessionInactiveExpiration: number;

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {
    this.refreshTokenExpiration = this.configService.get<number>(
      'REFRESH_TOKEN_EXPIRATION_DAYS',
      14,
    );
    this.sessionInactiveExpiration = this.configService.get<number>(
      'SESSION_INACTIVE_EXPIRATION_DAYS',
      7,
    );
  }

  /**
   * Cria nova sessão e retorna refresh token
   */
  async createSession(sessionData: SessionData): Promise<string> {
    const refreshToken = this.generateSecureToken();
    const refreshTokenHash = this.hashToken(refreshToken);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.refreshTokenExpiration);

    await this.prisma.session.create({
      data: {
        userId: sessionData.userId,
        refreshTokenHash,
        deviceFingerprint: sessionData.deviceFingerprint,
        ipAddress: sessionData.ipAddress,
        userAgent: sessionData.userAgent,
        riskScore: sessionData.riskScore || 0,
        expiresAt,
      },
    });

    return refreshToken;
  }

  /**
   * Valida refresh token e retorna dados da sessão
   */
  async validateRefreshToken(refreshToken: string): Promise<{
    isValid: boolean;
    sessionId?: string;
    userId?: string;
    deviceFingerprint?: string;
    error?: string;
  }> {
    const refreshTokenHash = this.hashToken(refreshToken);

    const session = await this.prisma.session.findFirst({
      where: {
        refreshTokenHash,
        isActive: true,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!session) {
      return {
        isValid: false,
        error: 'Refresh token inválido ou expirado',
      };
    }

    // Atualizar último uso
    await this.prisma.session.update({
      where: { id: session.id },
      data: { lastUsedAt: new Date() },
    });

    return {
      isValid: true,
      sessionId: session.id,
      userId: session.userId,
      deviceFingerprint: session.deviceFingerprint || undefined,
    };
  }

  /**
   * Rotaciona refresh token
   */
  async rotateRefreshToken(
    oldRefreshToken: string,
    newDeviceData?: Partial<SessionData>,
  ): Promise<{ newRefreshToken: string; sessionId: string } | null> {
    const oldTokenHash = this.hashToken(oldRefreshToken);

    const session = await this.prisma.session.findFirst({
      where: {
        refreshTokenHash: oldTokenHash,
        isActive: true,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!session) {
      return null;
    }

    // Detectar reutilização de token (possível ataque)
    if (
      session.lastUsedAt &&
      Date.now() - session.lastUsedAt.getTime() < 1000
    ) {
      // Token usado muito recentemente, possível reutilização
      await this.revokeSession(session.id);
      throw new Error(
        'Token reutilizado detectado. Sessão revogada por segurança.',
      );
    }

    const newRefreshToken = this.generateSecureToken();
    const newTokenHash = this.hashToken(newRefreshToken);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.refreshTokenExpiration);

    await this.prisma.session.update({
      where: { id: session.id },
      data: {
        refreshTokenHash: newTokenHash,
        expiresAt,
        lastUsedAt: new Date(),
        ipAddress: newDeviceData?.ipAddress || session.ipAddress,
        userAgent: newDeviceData?.userAgent || session.userAgent,
        riskScore: newDeviceData?.riskScore || session.riskScore,
      },
    });

    return {
      newRefreshToken,
      sessionId: session.id,
    };
  }

  /**
   * Lista sessões ativas de um usuário
   */
  async getUserActiveSessions(userId: string) {
    return this.prisma.session.findMany({
      where: {
        userId,
        isActive: true,
        expiresAt: {
          gt: new Date(),
        },
      },
      orderBy: {
        lastUsedAt: 'desc',
      },
      select: {
        id: true,
        deviceFingerprint: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
        lastUsedAt: true,
        riskScore: true,
      },
    });
  }

  /**
   * Revoga uma sessão específica
   */
  async revokeSession(sessionId: string): Promise<void> {
    await this.prisma.session.update({
      where: { id: sessionId },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });
  }

  /**
   * Revoga sessão por refresh token
   */
  async revokeSessionByToken(refreshToken: string): Promise<void> {
    const refreshTokenHash = this.hashToken(refreshToken);

    await this.prisma.session.updateMany({
      where: { refreshTokenHash },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });
  }

  /**
   * Revoga todas as sessões de um usuário
   */
  async revokeAllUserSessions(userId: string): Promise<number> {
    const result = await this.prisma.session.updateMany({
      where: {
        userId,
        isActive: true,
      },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });

    return result.count;
  }

  /**
   * Revoga todas as sessões exceto a atual
   */
  async revokeOtherUserSessions(
    userId: string,
    currentSessionId: string,
  ): Promise<number> {
    const result = await this.prisma.session.updateMany({
      where: {
        userId,
        isActive: true,
        id: {
          not: currentSessionId,
        },
      },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });

    return result.count;
  }

  /**
   * Limpa sessões expiradas ou inativas
   */
  async cleanupSessions(): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.sessionInactiveExpiration);

    const result = await this.prisma.session.deleteMany({
      where: {
        OR: [
          {
            expiresAt: {
              lt: new Date(),
            },
          },
          {
            isActive: false,
            revokedAt: {
              lt: cutoffDate,
            },
          },
          {
            lastUsedAt: {
              lt: cutoffDate,
            },
          },
        ],
      },
    });

    return result.count;
  }

  /**
   * Gera um device fingerprint básico
   */
  generateDeviceFingerprint(userAgent: string, ip: string): string {
    const data = `${userAgent}:${ip}`;
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Obtém eventos de sessão do usuário para auditoria
   */
  async getUserSessionEvents(
    userId: string,
    limit: number = 50,
  ): Promise<
    Array<{
      id: string;
      action: string;
      timestamp: Date;
      ipAddress?: string;
      userAgent?: string;
      result: string;
      reason?: string;
    }>
  > {
    const events = await this.prisma.auditLog.findMany({
      where: {
        actorId: userId,
        action: {
          in: [
            'LOGIN',
            'LOGOUT',
            'TOKEN_REFRESH',
            'SESSION_REVOKED',
            'MFA_VERIFIED',
          ],
        },
      },
      orderBy: {
        timestamp: 'desc',
      },
      take: limit,
      select: {
        id: true,
        action: true,
        timestamp: true,
        ipAddress: true,
        userAgent: true,
        result: true,
        reason: true,
      },
    });

    return events.map((event) => ({
      ...event,
      ipAddress: event.ipAddress || undefined,
      userAgent: event.userAgent || undefined,
      result: event.result.toString(),
      reason: event.reason || undefined,
    }));
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
