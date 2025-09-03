import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma.service';
import { DeviceInfo } from '../../auth/services/device-management.service';

export interface DeviceLoginNotification {
  userId: string;
  userEmail: string;
  deviceInfo: DeviceInfo;
  loginTime: Date;
  ipAddress: string;
  isNewDevice: boolean;
  isNewLocation: boolean;
  riskScore: number;
}

export interface SuspiciousActivityNotification {
  userId: string;
  userEmail: string;
  activityType: string;
  description: string;
  riskScore: number;
  timestamp: Date;
  ipAddress?: string;
  deviceInfo?: Partial<DeviceInfo>;
}

@Injectable()
export class DeviceNotificationService {
  private readonly logger = new Logger(DeviceNotificationService.name);
  private readonly notificationsEnabled: boolean;
  private readonly suspiciousActivityThreshold: number;

  constructor(
    private mailerService: MailerService,
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    this.notificationsEnabled = this.configService.get<boolean>(
      'NEW_DEVICE_NOTIFICATION_ENABLED',
      true,
    );
    this.suspiciousActivityThreshold = this.configService.get<number>(
      'SUSPICIOUS_ACTIVITY_THRESHOLD',
      80,
    );
  }

  /**
   * Envia notificação de novo dispositivo/localização
   */
  async sendNewDeviceNotification(
    notification: DeviceLoginNotification,
  ): Promise<void> {
    if (!this.notificationsEnabled) {
      this.logger.debug('Notificações de dispositivo desabilitadas');
      return;
    }

    try {
      const subject = notification.isNewDevice
        ? 'Novo dispositivo detectado em sua conta FUNAC'
        : 'Login de nova localização detectado em sua conta FUNAC';

      const template = this.buildNewDeviceEmailTemplate(notification);

      await this.mailerService.sendMail({
        to: notification.userEmail,
        subject,
        html: template,
      });

      this.logger.log(
        `Notificação de novo dispositivo enviada para ${notification.userEmail}`,
      );

      // Registrar envio na auditoria
      await this.prisma.auditLog.create({
        data: {
          actorId: notification.userId,
          action: 'NEW_DEVICE_NOTIFICATION_SENT',
          targetType: 'User',
          targetId: notification.userId,
          result: 'SUCCESS',
          reason: notification.isNewDevice ? 'New device' : 'New location',
          metadata: {
            deviceFingerprint: notification.deviceInfo.fingerprint,
            browser: notification.deviceInfo.browser,
            os: notification.deviceInfo.os,
            riskScore: notification.riskScore,
          },
          ipAddress: notification.ipAddress,
          timestamp: new Date(),
        },
      });
    } catch (error) {
      this.logger.error(
        `Erro ao enviar notificação para ${notification.userEmail}:`,
        error,
      );

      // Registrar falha na auditoria
      await this.prisma.auditLog.create({
        data: {
          actorId: notification.userId,
          action: 'NEW_DEVICE_NOTIFICATION_FAILED',
          targetType: 'User',
          targetId: notification.userId,
          result: 'FAILURE',
          reason: error instanceof Error ? error.message : 'Unknown error',
          ipAddress: notification.ipAddress,
          timestamp: new Date(),
        },
      });
    }
  }

  /**
   * Envia notificação de atividade suspeita
   */
  async sendSuspiciousActivityNotification(
    notification: SuspiciousActivityNotification,
  ): Promise<void> {
    if (notification.riskScore < this.suspiciousActivityThreshold) {
      this.logger.debug('Score de risco abaixo do threshold para notificação');
      return;
    }

    try {
      const subject = 'Atividade suspeita detectada em sua conta FUNAC';
      const template = this.buildSuspiciousActivityEmailTemplate(notification);

      await this.mailerService.sendMail({
        to: notification.userEmail,
        subject,
        html: template,
      });

      this.logger.warn(
        `Notificação de atividade suspeita enviada para ${notification.userEmail}`,
      );

      // Registrar envio na auditoria
      await this.prisma.auditLog.create({
        data: {
          actorId: notification.userId,
          action: 'SUSPICIOUS_ACTIVITY_NOTIFICATION_SENT',
          targetType: 'User',
          targetId: notification.userId,
          result: 'SUCCESS',
          reason: notification.activityType,
          metadata: {
            description: notification.description,
            riskScore: notification.riskScore,
            deviceInfo: notification.deviceInfo,
          },
          ipAddress: notification.ipAddress,
          timestamp: new Date(),
        },
      });
    } catch (error) {
      this.logger.error(
        `Erro ao enviar notificação de atividade suspeita para ${notification.userEmail}:`,
        error,
      );
    }
  }

  /**
   * Envia relatório semanal de segurança
   */
  async sendWeeklySecurityReport(userId: string): Promise<void> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { email: true, firstName: true, lastName: true },
      });

      if (!user) {
        this.logger.warn(`Usuário ${userId} não encontrado para relatório`);
        return;
      }

      // Coletar estatísticas da última semana
      const weekAgo = new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);

      const [loginEvents, sessionEvents, suspiciousEvents] = await Promise.all([
        this.prisma.auditLog.count({
          where: {
            actorId: userId,
            action: 'LOGIN',
            timestamp: { gte: weekAgo },
            result: 'SUCCESS',
          },
        }),
        this.prisma.session.count({
          where: {
            userId,
            createdAt: { gte: weekAgo },
          },
        }),
        this.prisma.auditLog.count({
          where: {
            actorId: userId,
            action: { contains: 'SUSPICIOUS' },
            timestamp: { gte: weekAgo },
          },
        }),
      ]);

      const template = this.buildWeeklyReportEmailTemplate({
        userName:
          `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'Usuário',
        loginCount: loginEvents,
        sessionCount: sessionEvents,
        suspiciousCount: suspiciousEvents,
        weekStart: weekAgo,
        weekEnd: new Date(),
      });

      await this.mailerService.sendMail({
        to: user.email,
        subject: 'Relatório Semanal de Segurança - FUNAC',
        html: template,
      });

      this.logger.log(`Relatório semanal enviado para ${user.email}`);
    } catch (error) {
      this.logger.error(
        `Erro ao enviar relatório semanal para usuário ${userId}:`,
        error,
      );
    }
  }

  /**
   * Template de email para novo dispositivo
   */
  private buildNewDeviceEmailTemplate(
    notification: DeviceLoginNotification,
  ): string {
    const { deviceInfo, loginTime, isNewDevice, riskScore } = notification;

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Novo Dispositivo Detectado</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #004085; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f8f9fa; }
            .alert { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px; }
            .device-info { background: white; padding: 15px; margin: 15px 0; border-radius: 4px; border-left: 4px solid #007bff; }
            .footer { background: #6c757d; color: white; padding: 15px; text-align: center; font-size: 12px; }
            .risk-score { font-weight: bold; color: ${riskScore > 70 ? '#dc3545' : riskScore > 40 ? '#ffc107' : '#28a745'}; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 FUNAC - Alerta de Segurança</h1>
            </div>
            
            <div class="content">
                <h2>${isNewDevice ? '🆕 Novo Dispositivo Detectado' : '🌍 Nova Localização Detectada'}</h2>
                
                <div class="alert">
                    <strong>⚠️ Atenção:</strong> ${
                      isNewDevice
                        ? 'Um novo dispositivo foi usado para acessar sua conta FUNAC.'
                        : 'Sua conta FUNAC foi acessada de uma nova localização.'
                    }
                </div>
                
                <div class="device-info">
                    <h3>📱 Detalhes do Dispositivo</h3>
                    <ul>
                        <li><strong>Navegador:</strong> ${deviceInfo.browser}</li>
                        <li><strong>Sistema Operacional:</strong> ${deviceInfo.os}</li>
                        <li><strong>Tipo de Dispositivo:</strong> ${deviceInfo.deviceType}</li>
                        <li><strong>Endereço IP:</strong> ${deviceInfo.ipAddress}</li>
                        ${
                          deviceInfo.location
                            ? `<li><strong>Localização:</strong> ${deviceInfo.location.city}, ${deviceInfo.location.region}, ${deviceInfo.location.country}</li>`
                            : ''
                        }
                        <li><strong>Data/Hora:</strong> ${loginTime.toLocaleString('pt-BR')}</li>
                        <li><strong>Score de Risco:</strong> <span class="risk-score">${riskScore}/100</span></li>
                    </ul>
                </div>
                
                <h3>🛡️ O que fazer?</h3>
                <p><strong>Se foi você:</strong></p>
                <ul>
                    <li>Nenhuma ação é necessária</li>
                    <li>Este dispositivo será lembrado para futuros acessos</li>
                </ul>
                
                <p><strong>Se NÃO foi você:</strong></p>
                <ul>
                    <li>🚨 <strong>Altere sua senha imediatamente</strong></li>
                    <li>🔐 Ative a autenticação de dois fatores</li>
                    <li>📱 Revogue todas as sessões ativas</li>
                    <li>📞 Entre em contato com o suporte TI</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>Esta é uma mensagem automática do sistema de segurança FUNAC.</p>
                <p>Não responda este email. Em caso de dúvidas, entre em contato com o suporte TI.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Template de email para atividade suspeita
   */
  private buildSuspiciousActivityEmailTemplate(
    notification: SuspiciousActivityNotification,
  ): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Atividade Suspeita Detectada</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background: #f8f9fa; }
            .alert { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; margin: 20px 0; border-radius: 4px; }
            .footer { background: #6c757d; color: white; padding: 15px; text-align: center; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 FUNAC - Alerta de Segurança Crítico</h1>
            </div>
            
            <div class="content">
                <h2>⚠️ Atividade Suspeita Detectada</h2>
                
                <div class="alert">
                    <strong>🚨 ALERTA:</strong> Detectamos atividade suspeita em sua conta FUNAC.
                </div>
                
                <h3>📊 Detalhes da Atividade</h3>
                <ul>
                    <li><strong>Tipo:</strong> ${notification.activityType}</li>
                    <li><strong>Descrição:</strong> ${notification.description}</li>
                    <li><strong>Score de Risco:</strong> <span style="color: #dc3545; font-weight: bold;">${notification.riskScore}/100</span></li>
                    <li><strong>Data/Hora:</strong> ${notification.timestamp.toLocaleString('pt-BR')}</li>
                    ${notification.ipAddress ? `<li><strong>IP:</strong> ${notification.ipAddress}</li>` : ''}
                </ul>
                
                <h3>🛡️ Ações Recomendadas</h3>
                <ol>
                    <li>🔐 <strong>Altere sua senha IMEDIATAMENTE</strong></li>
                    <li>🔑 Ative a autenticação de dois fatores</li>
                    <li>📱 Revogue todas as sessões ativas</li>
                    <li>🔍 Verifique atividades recentes na conta</li>
                    <li>📞 <strong>Entre em contato com o suporte TI urgentemente</strong></li>
                </ol>
            </div>
            
            <div class="footer">
                <p>Esta é uma mensagem automática do sistema de segurança FUNAC.</p>
                <p><strong>URGENTE:</strong> Não ignore este alerta. Entre em contato com o suporte TI imediatamente.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Template de relatório semanal
   */
  private buildWeeklyReportEmailTemplate(data: {
    userName: string;
    loginCount: number;
    sessionCount: number;
    suspiciousCount: number;
    weekStart: Date;
    weekEnd: Date;
  }): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Relatório Semanal de Segurança</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #007bff; color: white; padding: 20px; text-align: center; }
            .stats { display: flex; justify-content: space-around; margin: 20px 0; }
            .stat-box { background: white; padding: 15px; text-align: center; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-number { font-size: 24px; font-weight: bold; color: #007bff; }
            .footer { background: #6c757d; color: white; padding: 15px; text-align: center; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📊 Relatório Semanal de Segurança</h1>
                <p>Período: ${data.weekStart.toLocaleDateString('pt-BR')} - ${data.weekEnd.toLocaleDateString('pt-BR')}</p>
            </div>
            
            <div class="content">
                <h2>Olá, ${data.userName}!</h2>
                <p>Aqui está o resumo da atividade de segurança de sua conta na última semana:</p>
                
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number">${data.loginCount}</div>
                        <div>Logins Realizados</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">${data.sessionCount}</div>
                        <div>Sessões Criadas</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" style="color: ${data.suspiciousCount > 0 ? '#dc3545' : '#28a745'}">${data.suspiciousCount}</div>
                        <div>Eventos Suspeitos</div>
                    </div>
                </div>
                
                ${
                  data.suspiciousCount > 0
                    ? `
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px;">
                    <strong>⚠️ Atenção:</strong> Foram detectados eventos suspeitos em sua conta. 
                    Verifique sua conta e entre em contato com o suporte se necessário.
                </div>
                `
                    : `
                <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; margin: 20px 0; border-radius: 4px;">
                    <strong>✅ Tudo certo:</strong> Nenhuma atividade suspeita foi detectada em sua conta esta semana.
                </div>
                `
                }
                
                <h3>💡 Dicas de Segurança</h3>
                <ul>
                    <li>🔐 Use senhas únicas e fortes</li>
                    <li>🔑 Mantenha a autenticação de dois fatores ativada</li>
                    <li>🚫 Não compartilhe suas credenciais</li>
                    <li>🔍 Revise regularmente as sessões ativas</li>
                </ul>
            </div>
            
            <div class="footer">
                <p>Relatório gerado automaticamente pelo sistema de segurança FUNAC.</p>
                <p>Para alterar suas preferências de notificação, acesse as configurações da conta.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }
}
