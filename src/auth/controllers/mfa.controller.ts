import {
  Controller,
  Post,
  Get,
  Body,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/auth.guards';
import { MfaService } from '../../security/mfa.service';
import { PrismaService } from '../../database/prisma.service';
import { AuditService } from '../../audit/audit.service';

interface AuthenticatedRequest {
  user: {
    userId: string;
    email: string;
    roles: string[];
    permissions: string[];
  };
}

interface MfaSetupDto {
  secret: string;
  token: string;
}

@ApiTags('MFA')
@Controller('auth/mfa')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class MfaController {
  constructor(
    private mfaService: MfaService,
    private prisma: PrismaService,
    private auditService: AuditService,
  ) {}

  @Get('setup')
  @ApiOperation({
    summary: 'Configurar MFA',
    description: 'Gera QR code para configuração do MFA',
  })
  @ApiResponse({
    status: 200,
    description: 'QR code e secret gerados com sucesso',
  })
  async setupMfa(@Request() req: AuthenticatedRequest) {
    const user = await this.prisma.user.findUnique({
      where: { id: req.user.userId },
    });

    if (!user) {
      throw new Error('Usuário não encontrado');
    }

    const { secret, otpauthUrl } = this.mfaService.generateSecret(user.email);
    const qrCode = await this.mfaService.generateQRCode(otpauthUrl);

    return {
      secret,
      qrCode,
      manualEntryKey: secret,
    };
  }

  @Post('setup/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verificar e ativar MFA',
    description: 'Verifica o código TOTP e ativa o MFA para o usuário',
  })
  async verifyAndEnableMfa(
    @Body() setupDto: MfaSetupDto,
    @Request() req: AuthenticatedRequest,
  ) {
    const isValid = this.mfaService.verifyToken(
      setupDto.secret,
      setupDto.token,
    );

    if (!isValid) {
      throw new Error('Código MFA inválido');
    }

    // Gerar códigos de recuperação
    const backupCodes = this.mfaService.generateBackupCodes();

    // Salvar MFA secret e códigos
    await this.prisma.user.update({
      where: { id: req.user.userId },
      data: {
        mfaEnabled: true,
        mfaSecret: setupDto.secret,
        mfaRecoveryCodes: backupCodes,
      },
    });

    // Log de auditoria
    await this.auditService.logAuthEvent({
      userId: req.user.userId,
      email: req.user.email,
      action: 'MFA_ENABLED',
      ipAddress: 'unknown',
      userAgent: 'unknown',
      reason: 'MFA configurado com sucesso',
    });

    return {
      message: 'MFA ativado com sucesso',
      backupCodes,
    };
  }

  @Post('disable')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Desativar MFA',
    description: 'Desativa o MFA para o usuário',
  })
  async disableMfa(
    @Body() body: { currentPassword: string },
    @Request() req: AuthenticatedRequest,
  ) {
    // Verificar senha atual para segurança
    const user = await this.prisma.user.findUnique({
      where: { id: req.user.userId },
    });

    if (!user) {
      throw new Error('Usuário não encontrado');
    }

    // TODO: Verificar senha atual
    // const isValidPassword = await this.passwordService.verifyPassword(
    //   user.passwordHash,
    //   body.currentPassword
    // );

    // if (!isValidPassword) {
    //   throw new Error('Senha atual inválida');
    // }

    // Desativar MFA
    await this.prisma.user.update({
      where: { id: req.user.userId },
      data: {
        mfaEnabled: false,
        mfaSecret: null,
        mfaRecoveryCodes: [],
      },
    });

    // Log de auditoria
    await this.auditService.logAuthEvent({
      userId: req.user.userId,
      email: req.user.email,
      action: 'MFA_DISABLED',
      ipAddress: 'unknown',
      userAgent: 'unknown',
      reason: 'MFA desativado pelo usuário',
    });

    return {
      message: 'MFA desativado com sucesso',
    };
  }

  @Get('status')
  @ApiOperation({
    summary: 'Status do MFA',
    description: 'Retorna o status atual do MFA do usuário',
  })
  async getMfaStatus(@Request() req: AuthenticatedRequest) {
    const user = await this.prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        mfaEnabled: true,
        mfaRecoveryCodes: true,
      },
    });

    return {
      enabled: user?.mfaEnabled || false,
      backupCodesCount: user?.mfaRecoveryCodes?.length || 0,
    };
  }

  @Post('backup-codes/regenerate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Regenerar códigos de backup',
    description: 'Gera novos códigos de backup para MFA',
  })
  async regenerateBackupCodes(@Request() req: AuthenticatedRequest) {
    const user = await this.prisma.user.findUnique({
      where: { id: req.user.userId },
    });

    if (!user?.mfaEnabled) {
      throw new Error('MFA não está ativado');
    }

    const backupCodes = this.mfaService.generateBackupCodes();

    await this.prisma.user.update({
      where: { id: req.user.userId },
      data: {
        mfaRecoveryCodes: backupCodes,
      },
    });

    // Log de auditoria
    await this.auditService.logAuthEvent({
      userId: req.user.userId,
      email: req.user.email,
      action: 'MFA_BACKUP_CODES_REGENERATED',
      ipAddress: 'unknown',
      userAgent: 'unknown',
      reason: 'Códigos de backup regenerados',
    });

    return {
      message: 'Códigos de backup regenerados com sucesso',
      backupCodes,
    };
  }
}
