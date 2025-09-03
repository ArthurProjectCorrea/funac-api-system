import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma.service';
import { TokenService } from './token.service';

@Injectable()
export class TokenCleanupService {
  private readonly logger = new Logger(TokenCleanupService.name);
  private readonly cleanupInterval: string;

  constructor(
    private prisma: PrismaService,
    private tokenService: TokenService,
    private configService: ConfigService,
  ) {
    this.cleanupInterval = this.configService.get<string>(
      'TOKEN_CLEANUP_CRON',
      '0 */1 * * *', // A cada hora por padrão
    );
  }

  /**
   * Limpeza automática de tokens expirados - executa a cada hora
   */
  @Cron(CronExpression.EVERY_HOUR)
  async cleanupExpiredTokens(): Promise<void> {
    this.logger.log('Iniciando limpeza de tokens expirados...');

    try {
      const deletedCount = await this.tokenService.cleanupExpiredTokens();
      this.logger.log(`Removidos ${deletedCount} tokens expirados`);
    } catch (error) {
      this.logger.error('Erro durante limpeza de tokens:', error);
    }
  }

  /**
   * Limpeza automática de sessões expiradas - executa a cada 6 horas
   */
  @Cron('0 */6 * * *')
  async cleanupExpiredSessions(): Promise<void> {
    this.logger.log('Iniciando limpeza de sessões expiradas...');

    try {
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
                lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 dias
              },
            },
          ],
        },
      });

      this.logger.log(`Removidas ${result.count} sessões expiradas/revogadas`);
    } catch (error) {
      this.logger.error('Erro durante limpeza de sessões:', error);
    }
  }

  /**
   * Limpeza de logs de auditoria antigos - executa diariamente
   */
  @Cron(CronExpression.EVERY_DAY_AT_2AM)
  async cleanupOldAuditLogs(): Promise<void> {
    const retentionDays = this.configService.get<number>(
      'AUDIT_LOG_RETENTION_DAYS',
      90,
    );

    this.logger.log(
      `Iniciando limpeza de logs de auditoria > ${retentionDays} dias...`,
    );

    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const result = await this.prisma.auditLog.deleteMany({
        where: {
          timestamp: {
            lt: cutoffDate,
          },
        },
      });

      this.logger.log(`Removidos ${result.count} logs de auditoria antigos`);
    } catch (error) {
      this.logger.error('Erro durante limpeza de logs de auditoria:', error);
    }
  }

  /**
   * Otimização do banco de dados - executa semanalmente
   */
  @Cron(CronExpression.EVERY_WEEK)
  async optimizeDatabase(): Promise<void> {
    this.logger.log('Iniciando otimização do banco de dados...');

    try {
      // Para PostgreSQL, executar VACUUM ANALYZE
      await this.prisma.$executeRaw`VACUUM ANALYZE;`;
      this.logger.log('Otimização do banco concluída');
    } catch (error: unknown) {
      this.logger.warn(
        'Otimização do banco não pôde ser executada:',
        error instanceof Error ? error.message : 'Erro desconhecido',
      );
    }
  }

  /**
   * Relatório de estatísticas de cleanup - executa diariamente
   */
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async generateCleanupReport(): Promise<void> {
    this.logger.log('Gerando relatório de limpeza...');

    try {
      const [activeTokensCount, activeSessionsCount, auditLogsCount] =
        await Promise.all([
          this.prisma.token.count({
            where: {
              expiresAt: {
                gt: new Date(),
              },
              usedAt: null,
            },
          }),
          this.prisma.session.count({
            where: {
              isActive: true,
              expiresAt: {
                gt: new Date(),
              },
            },
          }),
          this.prisma.auditLog.count(),
        ]);

      this.logger.log(`Relatório de limpeza:
        - Tokens ativos: ${activeTokensCount}
        - Sessões ativas: ${activeSessionsCount}
        - Total de logs de auditoria: ${auditLogsCount}
      `);
    } catch (error) {
      this.logger.error('Erro ao gerar relatório de limpeza:', error);
    }
  }

  /**
   * Executa limpeza manual de emergência
   */
  async emergencyCleanup(): Promise<{
    tokensDeleted: number;
    sessionsDeleted: number;
    auditLogsDeleted: number;
  }> {
    this.logger.warn('Executando limpeza manual de emergência...');

    try {
      const [tokensDeleted, sessionsResult, auditLogsResult] =
        await Promise.all([
          this.tokenService.cleanupExpiredTokens(),
          this.prisma.session.deleteMany({
            where: {
              OR: [{ expiresAt: { lt: new Date() } }, { isActive: false }],
            },
          }),
          this.prisma.auditLog.deleteMany({
            where: {
              timestamp: {
                lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 dias
              },
            },
          }),
        ]);

      const result = {
        tokensDeleted,
        sessionsDeleted: sessionsResult.count,
        auditLogsDeleted: auditLogsResult.count,
      };

      this.logger.warn(`Limpeza de emergência concluída:`, result);
      return result;
    } catch (error) {
      this.logger.error('Erro durante limpeza de emergência:', error);
      throw error;
    }
  }
}
