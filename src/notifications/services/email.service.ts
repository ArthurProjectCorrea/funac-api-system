import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private readonly baseUrl: string;
  private readonly frontendUrl: string;

  constructor(
    private mailerService: MailerService,
    private configService: ConfigService,
  ) {
    this.baseUrl = this.configService.get<string>(
      'API_BASE_URL',
      'http://localhost:3000',
    );
    this.frontendUrl = this.configService.get<string>(
      'FRONTEND_URL',
      'http://localhost:3001',
    );
  }

  /**
   * Envia email de verificação
   */
  async sendEmailVerification(email: string, token: string): Promise<void> {
    try {
      const verificationUrl = `${this.frontendUrl}/auth/verify-email?token=${token}`;

      await this.mailerService.sendMail({
        to: email,
        subject: 'Verificação de Email - FUNAC',
        html: this.buildEmailVerificationTemplate(verificationUrl),
      });

      this.logger.log(`Email de verificação enviado para ${email}`);
    } catch (error) {
      this.logger.error(
        `Erro ao enviar email de verificação para ${email}:`,
        error,
      );
      throw error;
    }
  }

  /**
   * Envia email de reset de senha
   */
  async sendPasswordReset(email: string, token: string): Promise<void> {
    try {
      const resetUrl = `${this.frontendUrl}/auth/reset-password?token=${token}`;

      await this.mailerService.sendMail({
        to: email,
        subject: 'Redefinição de Senha - FUNAC',
        html: this.buildPasswordResetTemplate(resetUrl),
      });

      this.logger.log(`Email de reset de senha enviado para ${email}`);
    } catch (error) {
      this.logger.error(`Erro ao enviar email de reset para ${email}:`, error);
      throw error;
    }
  }

  /**
   * Envia email de convite
   */
  async sendUserInvitation(
    email: string,
    token: string,
    tempPassword: string,
  ): Promise<void> {
    try {
      const inviteUrl = `${this.frontendUrl}/auth/accept-invite?token=${token}`;

      await this.mailerService.sendMail({
        to: email,
        subject: 'Convite para FUNAC - Acesse sua conta',
        html: this.buildInvitationTemplate(inviteUrl, tempPassword),
      });

      this.logger.log(`Email de convite enviado para ${email}`);
    } catch (error) {
      this.logger.error(`Erro ao enviar convite para ${email}:`, error);
      throw error;
    }
  }

  /**
   * Template de verificação de email
   */
  private buildEmailVerificationTemplate(verificationUrl: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Verificação de Email</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #004085; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { padding: 20px; background: #f8f9fa; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .button:hover { background: #0056b3; }
          .footer { text-align: center; font-size: 12px; color: #666; margin-top: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 FUNAC - Verificação de Email</h1>
          </div>
          
          <div class="content">
            <h2>Confirme seu endereço de email</h2>
            
            <p>Olá! Para concluir seu cadastro na plataforma FUNAC, você precisa verificar seu endereço de email.</p>
            
            <p>Clique no botão abaixo para confirmar:</p>
            
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verificar Email</a>
            </div>
            
            <p><strong>⚠️ Importante:</strong></p>
            <ul>
              <li>Este link expira em 60 minutos</li>
              <li>Use apenas uma vez</li>
              <li>Se você não solicitou esta verificação, ignore este email</li>
            </ul>
            
            <p>Se o botão não funcionar, copie e cole este link no seu navegador:</p>
            <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 4px;">
              ${verificationUrl}
            </p>
          </div>
          
          <div class="footer">
            <p>Esta é uma mensagem automática do sistema FUNAC.</p>
            <p>Não responda este email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Template de reset de senha
   */
  private buildPasswordResetTemplate(resetUrl: string): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Redefinição de Senha</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { padding: 20px; background: #f8f9fa; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; padding: 12px 24px; background: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .button:hover { background: #c82333; }
          .alert { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; border-radius: 4px; }
          .footer { text-align: center; font-size: 12px; color: #666; margin-top: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔑 FUNAC - Redefinição de Senha</h1>
          </div>
          
          <div class="content">
            <h2>Redefina sua senha</h2>
            
            <p>Você solicitou a redefinição da sua senha na plataforma FUNAC.</p>
            
            <div class="alert">
              <strong>⚠️ Atenção:</strong> Se você não solicitou esta alteração, ignore este email e entre em contato com o suporte imediatamente.
            </div>
            
            <p>Clique no botão abaixo para definir uma nova senha:</p>
            
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Redefinir Senha</a>
            </div>
            
            <p><strong>🔒 Segurança:</strong></p>
            <ul>
              <li>Este link expira em 20 minutos</li>
              <li>Use apenas uma vez</li>
              <li>Suas sessões ativas serão encerradas após a redefinição</li>
              <li>Escolha uma senha forte com pelo menos 12 caracteres</li>
            </ul>
            
            <p>Se o botão não funcionar, copie e cole este link no seu navegador:</p>
            <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 4px;">
              ${resetUrl}
            </p>
          </div>
          
          <div class="footer">
            <p>Esta é uma mensagem automática do sistema FUNAC.</p>
            <p>Não responda este email.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Template de convite
   */
  private buildInvitationTemplate(
    inviteUrl: string,
    tempPassword: string,
  ): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Convite para FUNAC</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { padding: 20px; background: #f8f9fa; border-radius: 0 0 8px 8px; }
          .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .button:hover { background: #218838; }
          .password-box { background: #e9ecef; padding: 15px; border-radius: 4px; margin: 15px 0; text-align: center; }
          .footer { text-align: center; font-size: 12px; color: #666; margin-top: 20px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Bem-vindo à FUNAC!</h1>
          </div>
          
          <div class="content">
            <h2>Você foi convidado a fazer parte da equipe</h2>
            
            <p>Parabéns! Você foi convidado para acessar a plataforma FUNAC. Para começar, você precisa ativar sua conta.</p>
            
            <p><strong>Senha temporária:</strong></p>
            <div class="password-box">
              <strong style="font-size: 18px; letter-spacing: 2px;">${tempPassword}</strong>
            </div>
            
            <p>Clique no botão abaixo para ativar sua conta:</p>
            
            <div style="text-align: center;">
              <a href="${inviteUrl}" class="button">Ativar Conta</a>
            </div>
            
            <p><strong>📋 Próximos passos:</strong></p>
            <ol>
              <li>Clique no link de ativação</li>
              <li>Faça login com seu email e a senha temporária</li>
              <li>Defina uma nova senha segura</li>
              <li>Configure a autenticação de dois fatores (MFA)</li>
            </ol>
            
            <p><strong>⚠️ Importante:</strong></p>
            <ul>
              <li>Este convite expira em 7 dias</li>
              <li>Altere a senha temporária no primeiro acesso</li>
              <li>Mantenha suas credenciais seguras</li>
            </ul>
            
            <p>Se o botão não funcionar, copie e cole este link no seu navegador:</p>
            <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 4px;">
              ${inviteUrl}
            </p>
          </div>
          
          <div class="footer">
            <p>Esta é uma mensagem automática do sistema FUNAC.</p>
            <p>Em caso de dúvidas, entre em contato com o administrador.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}
