import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { PrismaService } from '../../database/prisma.service';
import { PasswordService } from '../../security/password.service';
import { TokenService } from './token.service';
import { SessionService } from './session.service';
import { RiskAssessmentService, LoginAttempt } from './risk-assessment.service';
import { DeviceManagementService } from './device-management.service';
import { TokenBlacklistService } from './token-blacklist.service';
import { AuditService } from '../../audit/audit.service';
import { DeviceNotificationService } from '../../notifications/services/device-notification.service';
import { EmailService } from '../../notifications/services/email.service';
import { UserStatus } from '@prisma/client';

export interface UserWithRoles {
  id: string;
  email: string;
  status: UserStatus;
  mfaEnabled: boolean;
  roles?: Array<{
    role: {
      name: string;
      permissions: Array<{
        permission: {
          name: string;
        };
      }>;
    };
  }>;
}

export interface LoginCredentials {
  email: string;
  password: string;
  ipAddress: string;
  userAgent: string;
}

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    status: UserStatus;
    mfaEnabled: boolean;
  };
  requireMfa?: boolean;
  mfaChallenge?: string;
}

export interface MfaVerification {
  code: string;
  sessionId: string;
}

@Injectable()
export class AuthService {
  private readonly accessTokenExpiration: string;

  constructor(
    private prisma: PrismaService,
    private passwordService: PasswordService,
    private tokenService: TokenService,
    private sessionService: SessionService,
    private riskAssessmentService: RiskAssessmentService,
    private deviceManagementService: DeviceManagementService,
    private tokenBlacklistService: TokenBlacklistService,
    private auditService: AuditService,
    private deviceNotificationService: DeviceNotificationService,
    private emailService: EmailService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {
    this.accessTokenExpiration = this.configService.get<string>(
      'JWT_ACCESS_EXPIRATION',
      '15m',
    );
  }

  /**
   * Realiza login com validação de risco
   */
  async login(credentials: LoginCredentials): Promise<LoginResult> {
    const { email, password, ipAddress, userAgent } = credentials;

    // Buscar usuário
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    // Registrar tentativa de login
    const loginAttempt: LoginAttempt = {
      userId: user?.id,
      email,
      ipAddress,
      userAgent,
      timestamp: new Date(),
      success: false,
    };

    try {
      // Validar usuário e senha
      if (
        !user ||
        !(await this.passwordService.verifyPassword(
          user.passwordHash,
          password,
        ))
      ) {
        await this.auditService.logAuthEvent({
          action: 'LOGIN_FAILED',
          email,
          ipAddress,
          userAgent,
          reason: 'Credenciais inválidas',
        });
        throw new UnauthorizedException('Credenciais inválidas');
      }

      // Verificar status do usuário
      if (user.status !== UserStatus.ACTIVE) {
        await this.auditService.logAuthEvent({
          userId: user.id,
          action: 'LOGIN_FAILED',
          email,
          ipAddress,
          userAgent,
          reason: `Status do usuário: ${user.status}`,
        });
        throw new UnauthorizedException('Conta não está ativa');
      }

      // Avaliar risco da tentativa
      const userHistory = await this.getUserLoginHistory(user.id);
      const riskAssessment = this.riskAssessmentService.assessLoginRisk(
        { ...loginAttempt, userId: user.id },
        userHistory,
      );

      // Bloquear se risco muito alto
      if (riskAssessment.shouldBlock) {
        await this.auditService.logAuthEvent({
          userId: user.id,
          action: 'LOGIN_BLOCKED',
          email,
          ipAddress,
          userAgent,
          reason: `Alto risco: ${riskAssessment.factors.join(', ')}`,
        });
        throw new UnauthorizedException('Login bloqueado por segurança');
      }

      // Verificar se requer MFA
      const requireMfa =
        user.mfaEnabled ||
        riskAssessment.requireMfa ||
        riskAssessment.requireStepUp;

      if (requireMfa && user.mfaSecret) {
        // Criar sessão temporária para MFA
        const tempSessionId = this.createTempMfaSession();

        await this.auditService.logAuthEvent({
          userId: user.id,
          action: 'MFA_REQUIRED',
          email,
          ipAddress,
          userAgent,
          reason: 'MFA obrigatório',
        });

        return {
          accessToken: '',
          refreshToken: '',
          user: {
            id: user.id,
            email: user.email,
            status: user.status,
            mfaEnabled: user.mfaEnabled,
          },
          requireMfa: true,
          mfaChallenge: tempSessionId,
        };
      }

      // Login bem-sucedido - criar sessão
      const result = await this.createUserSession(
        user,
        ipAddress,
        userAgent,
        riskAssessment.riskScore,
      );

      // Atualizar último login
      await this.prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });

      await this.auditService.logAuthEvent({
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        email,
        ipAddress,
        userAgent,
        reason: 'Login bem-sucedido',
      });

      return result;
    } catch (error) {
      // Registrar histórico da tentativa falhada
      this.recordFailedLoginAttempt();
      throw error;
    }
  }

  /**
   * Verifica código MFA e completa o login
   */
  async verifyMfa(
    verification: MfaVerification,
    ipAddress: string,
    userAgent: string,
  ): Promise<LoginResult> {
    const { code } = verification;

    // Validar sessão temporária de MFA
    const tempSession = this.validateTempMfaSession();
    if (!tempSession) {
      throw new UnauthorizedException('Sessão MFA inválida ou expirada');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: tempSession.userId },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user || !user.mfaSecret) {
      throw new UnauthorizedException('Usuário ou MFA não encontrado');
    }

    // Verificar código TOTP (implementação simplificada para agora)
    // Em produção, usar a biblioteca speakeasy corretamente
    const verified = code === '123456' || code.length === 6; // Mock para desenvolvimento

    if (!verified) {
      await this.auditService.logAuthEvent({
        userId: user.id,
        action: 'MFA_FAILED',
        email: user.email,
        ipAddress,
        userAgent,
        reason: 'Código MFA inválido',
      });
      throw new UnauthorizedException('Código MFA inválido');
    }

    // Remover sessão temporária
    this.removeTempMfaSession();

    // Criar sessão real
    const result = await this.createUserSession(
      user,
      ipAddress,
      userAgent,
      tempSession.riskScore,
    );

    // Atualizar último login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    await this.auditService.logAuthEvent({
      userId: user.id,
      action: 'MFA_SUCCESS',
      email: user.email,
      ipAddress,
      userAgent,
      reason: 'MFA verificado com sucesso',
    });

    return result;
  }

  /**
   * Renova access token usando refresh token
   */
  async refreshTokens(
    refreshToken: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    // Validar e rotacionar refresh token
    const result = await this.sessionService.rotateRefreshToken(refreshToken, {
      ipAddress,
      userAgent,
    });

    if (!result) {
      throw new UnauthorizedException('Refresh token inválido');
    }

    // Buscar usuário da sessão
    const session = await this.prisma.session.findUnique({
      where: { id: result.sessionId },
      include: { user: true },
    });

    if (!session) {
      throw new UnauthorizedException('Sessão não encontrada');
    }

    // Gerar novo access token
    const accessToken = await this.generateAccessToken(session.user);

    await this.auditService.logAuthEvent({
      userId: session.user.id,
      action: 'TOKEN_REFRESH',
      email: session.user.email,
      ipAddress,
      userAgent,
      reason: 'Tokens renovados',
    });

    return {
      accessToken,
      refreshToken: result.newRefreshToken,
    };
  }

  /**
   * Realiza logout
   */
  async logout(
    refreshToken: string,
    currentAccessTokenId?: string,
  ): Promise<void> {
    await this.sessionService.revokeSessionByToken(refreshToken);

    // Adicionar access token atual à blacklist se fornecido
    if (currentAccessTokenId) {
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 15); // TTL do access token
      await this.tokenBlacklistService.blacklistToken(
        currentAccessTokenId,
        expiresAt,
      );
    }

    // Log de auditoria será feito pelo interceptor
  }

  /**
   * Logout de todos os dispositivos
   */
  async logoutAll(
    userId: string,
    currentSessionId?: string,
    currentAccessTokenId?: string,
  ): Promise<number> {
    let revokedCount: number;

    if (currentSessionId) {
      revokedCount = await this.sessionService.revokeOtherUserSessions(
        userId,
        currentSessionId,
      );
    } else {
      revokedCount = await this.sessionService.revokeAllUserSessions(userId);
    }

    // Adicionar access token atual à blacklist para invalidar imediatamente
    if (currentAccessTokenId) {
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 15); // TTL do access token
      await this.tokenBlacklistService.blacklistToken(
        currentAccessTokenId,
        expiresAt,
      );
    }

    await this.auditService.logAuthEvent({
      userId,
      action: 'LOGOUT_ALL',
      reason: `${revokedCount} sessões revogadas`,
    });

    return revokedCount;
  }

  /**
   * Cria sessão do usuário e retorna tokens
   */
  private async createUserSession(
    user: UserWithRoles,
    _ipAddress: string,
    _userAgent: string,
    riskScore: number,
  ): Promise<LoginResult> {
    // Detectar novo dispositivo/localização
    const deviceDetection = await this.deviceManagementService.detectNewDevice(
      user.id,
      _userAgent,
      _ipAddress,
    );

    // Atualizar score de risco baseado na detecção
    const finalRiskScore = Math.max(riskScore, deviceDetection.riskScore);

    // Gerar device fingerprint usando o serviço dedicado
    const deviceFingerprint = deviceDetection.deviceInfo.fingerprint;

    // Criar sessão
    const refreshToken = await this.sessionService.createSession({
      userId: user.id,
      deviceFingerprint,
      ipAddress: _ipAddress,
      userAgent: _userAgent,
      riskScore: finalRiskScore,
    });

    // Gerar access token
    const accessToken = await this.generateAccessToken(user);

    // Enviar notificação se necessário (não bloquear o login)
    if (deviceDetection.shouldNotify) {
      // Executar notificação de forma assíncrona
      setImmediate(() => {
        this.deviceNotificationService
          .sendNewDeviceNotification({
            userId: user.id,
            userEmail: user.email,
            deviceInfo: deviceDetection.deviceInfo,
            loginTime: new Date(),
            ipAddress: _ipAddress,
            isNewDevice: deviceDetection.isNewDevice,
            isNewLocation: deviceDetection.isNewLocation,
            riskScore: finalRiskScore,
          })
          .catch((error) => {
            // Log o erro mas não falhar o login
            console.error(
              'Erro ao enviar notificação de novo dispositivo:',
              error,
            );
          });
      });
    }

    // Atualizar último login do usuário
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        status: user.status,
        mfaEnabled: user.mfaEnabled,
      },
    };
  }

  /**
   * Gera access token JWT
   */
  private async generateAccessToken(user: UserWithRoles): Promise<string> {
    const tokenId = crypto.randomUUID(); // Gerar JTI único

    const payload = {
      sub: user.id,
      jti: tokenId, // Token ID para blacklist
      email: user.email,
      status: user.status,
      roles: user.roles?.map((ur) => ur.role.name) || [],
      permissions: this.extractPermissions(user.roles || []),
    };

    return this.jwtService.signAsync(payload, {
      expiresIn: this.accessTokenExpiration,
    });
  }

  /**
   * Extrai permissões do usuário
   */
  private extractPermissions(userRoles: UserWithRoles['roles']): string[] {
    const permissions = new Set<string>();

    userRoles?.forEach((userRole) => {
      userRole.role.permissions.forEach((rp) => {
        permissions.add(rp.permission.name);
      });
    });

    return Array.from(permissions);
  }

  /**
   * Busca histórico de login do usuário
   */
  private async getUserLoginHistory(userId: string): Promise<LoginAttempt[]> {
    // Em produção, buscar de uma tabela específica de login attempts
    // Por agora, simular com audit logs
    const auditLogs = await this.prisma.auditLog.findMany({
      where: {
        actorId: userId,
        action: {
          in: ['LOGIN_SUCCESS', 'LOGIN_FAILED'],
        },
        timestamp: {
          gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // últimos 30 dias
        },
      },
      orderBy: {
        timestamp: 'desc',
      },
      take: 50,
    });

    return auditLogs.map((log) => ({
      userId: log.actorId || undefined,
      email: ((log.metadata as Record<string, unknown>)?.email as string) || '',
      ipAddress: log.ipAddress || '',
      userAgent: log.userAgent || '',
      timestamp: log.timestamp,
      success: log.action === 'LOGIN_SUCCESS',
    }));
  }

  /**
   * Registra tentativa de login falhada
   */
  private recordFailedLoginAttempt(): void {
    // Em produção, salvar em tabela específica para rate limiting
    // Por agora, usar apenas audit log
  }

  /**
   * Cria sessão temporária para MFA
   */
  private createTempMfaSession(): string {
    // Em produção, usar Redis ou cache temporário
    // Por agora, simular com ID único
    const sessionId = Math.random().toString(36) + Date.now().toString(36);

    // Salvar temporariamente (implementar cache Redis)
    return sessionId;
  }

  /**
   * Valida sessão temporária de MFA
   */
  private validateTempMfaSession(): {
    userId: string;
    riskScore: number;
  } | null {
    // Em produção, buscar do Redis
    // Por agora, retornar mock
    return null;
  }

  /**
   * Remove sessão temporária de MFA
   */
  private removeTempMfaSession(): void {
    // Implementar remoção do cache
  }

  /**
   * Solicita reset de senha
   */
  async forgotPassword(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      // Por segurança, não revelar se o email existe
      await this.auditService.logAuthEvent({
        email,
        action: 'PASSWORD_RESET_REQUESTED',
        ipAddress: 'unknown',
        userAgent: 'unknown',
        reason: 'Email não encontrado',
      });
      return;
    }

    // Gerar token de reset
    const resetToken = await this.tokenService.generatePasswordResetToken(
      user.id,
    );

    // Enviar email com link de reset
    await this.emailService.sendPasswordReset(user.email, resetToken);

    await this.auditService.logAuthEvent({
      userId: user.id,
      email: user.email,
      action: 'PASSWORD_RESET_REQUESTED',
      ipAddress: 'unknown',
      userAgent: 'unknown',
      reason: 'Token de reset gerado',
    });
  }

  /**
   * Redefine a senha do usuário
   */
  async resetPassword(userId: string, newPassword: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }

    // Validar política de senha
    const passwordValidation =
      this.passwordService.validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      throw new UnauthorizedException(passwordValidation.errors.join(', '));
    }

    // Hash da nova senha
    const passwordHash = await this.passwordService.hashPassword(newPassword);

    // Atualizar senha e invalidar todas as sessões
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash,
        passwordUpdatedAt: new Date(),
      },
    });

    // Revogar todas as sessões ativas
    await this.sessionService.revokeAllUserSessions(userId);

    await this.auditService.logAuthEvent({
      userId: user.id,
      email: user.email,
      action: 'PASSWORD_RESET_COMPLETED',
      ipAddress: 'unknown',
      userAgent: 'unknown',
      reason: 'Senha redefinida com sucesso',
    });
  }

  /**
   * Verifica o email do usuário
   */
  async verifyEmail(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }

    // Atualizar status do usuário
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        emailVerified: true,
        emailVerifiedAt: new Date(),
        status:
          user.status === UserStatus.PENDING_EMAIL_VERIFICATION
            ? UserStatus.ACTIVE
            : user.status,
      },
    });

    await this.auditService.logAuthEvent({
      userId: user.id,
      email: user.email,
      action: 'EMAIL_VERIFIED',
      ipAddress: 'unknown',
      userAgent: 'unknown',
      reason: 'Email verificado com sucesso',
    });
  }

  /**
   * Reenvia email de verificação
   */
  async resendEmailVerification(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user || user.emailVerified) {
      // Por segurança, não revelar se o email existe ou já foi verificado
      return;
    }

    // Gerar novo token de verificação
    const verificationToken =
      await this.tokenService.generateEmailVerificationToken(user.id);

    // Enviar email de verificação
    await this.emailService.sendEmailVerification(
      user.email,
      verificationToken,
    );

    await this.auditService.logAuthEvent({
      userId: user.id,
      email: user.email,
      action: 'EMAIL_VERIFICATION_RESENT',
      ipAddress: 'unknown',
      userAgent: 'unknown',
      reason: 'Novo token de verificação gerado',
    });
  }
}
