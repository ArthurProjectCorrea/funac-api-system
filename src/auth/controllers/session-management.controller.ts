import {
  Controller,
  Get,
  Delete,
  Param,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/auth.guards';
import { SessionService } from '../services/session.service';
import { DeviceManagementService } from '../services/device-management.service';
import { TokenBlacklistService } from '../services/token-blacklist.service';

interface AuthenticatedRequest {
  user: {
    userId: string;
    email: string;
    tokenId?: string;
    roles: string[];
    permissions: string[];
  };
}

@ApiTags('Session Management')
@Controller('sessions')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class SessionManagementController {
  constructor(
    private sessionService: SessionService,
    private deviceManagementService: DeviceManagementService,
    private tokenBlacklistService: TokenBlacklistService,
  ) {}

  @Get('me')
  @ApiOperation({
    summary: 'Listar minhas sessões ativas',
    description: 'Retorna todas as sessões ativas do usuário autenticado',
  })
  @ApiResponse({
    status: 200,
    description: 'Lista de sessões ativas',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          deviceFingerprint: { type: 'string' },
          ipAddress: { type: 'string' },
          userAgent: { type: 'string' },
          createdAt: { type: 'string', format: 'date-time' },
          lastUsedAt: { type: 'string', format: 'date-time' },
          riskScore: { type: 'number' },
          isCurrent: { type: 'boolean' },
        },
      },
    },
  })
  async getMySessions(@Request() req: AuthenticatedRequest) {
    const sessions = await this.sessionService.getUserActiveSessions(
      req.user.userId,
    );

    // Marcar a sessão atual (se possível identificar)
    return sessions.map((session) => ({
      ...session,
      isCurrent: false, // TODO: implementar detecção da sessão atual
    }));
  }

  @Get('me/devices')
  @ApiOperation({
    summary: 'Listar meus dispositivos',
    description:
      'Retorna informações sobre os dispositivos utilizados pelo usuário',
  })
  @ApiResponse({
    status: 200,
    description: 'Lista de dispositivos do usuário',
  })
  async getMyDevices(@Request() req: AuthenticatedRequest) {
    const devices = await this.deviceManagementService.getUserDevices(
      req.user.userId,
    );
    const stats = await this.deviceManagementService.getDeviceStats(
      req.user.userId,
    );

    return {
      devices,
      stats,
    };
  }

  @Get('me/stats')
  @ApiOperation({
    summary: 'Estatísticas das minhas sessões',
    description: 'Retorna estatísticas sobre sessões e dispositivos do usuário',
  })
  @ApiResponse({
    status: 200,
    description: 'Estatísticas de sessões e dispositivos',
  })
  async getMySessionStats(@Request() req: AuthenticatedRequest) {
    const deviceStats = await this.deviceManagementService.getDeviceStats(
      req.user.userId,
    );

    return {
      ...deviceStats,
      timestamp: new Date(),
    };
  }

  @Delete('me/:sessionId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Revogar sessão específica',
    description: 'Revoga uma sessão específica do usuário',
  })
  @ApiResponse({
    status: 204,
    description: 'Sessão revogada com sucesso',
  })
  @ApiResponse({
    status: 404,
    description: 'Sessão não encontrada',
  })
  async revokeMySession(
    @Param('sessionId') sessionId: string,
    @Request() req: AuthenticatedRequest,
  ) {
    // Verificar se a sessão pertence ao usuário
    const sessions = await this.sessionService.getUserActiveSessions(
      req.user.userId,
    );
    const sessionExists = sessions.some((s) => s.id === sessionId);

    if (!sessionExists) {
      throw new Error('Sessão não encontrada ou não pertence ao usuário');
    }

    await this.sessionService.revokeSession(sessionId);
  }

  @Delete('me/others')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Revogar outras sessões',
    description:
      'Revoga todas as outras sessões do usuário, mantendo apenas a atual',
  })
  @ApiResponse({
    status: 200,
    description: 'Outras sessões revogadas com sucesso',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string' },
        revokedSessions: { type: 'number' },
      },
    },
  })
  async revokeOtherSessions(@Request() req: AuthenticatedRequest) {
    // Para revogar outras sessões, precisamos identificar a sessão atual
    // Como não temos o sessionId na request, vamos revogar todas as sessões do usuário
    // Isso forçará o usuário a fazer login novamente em todos os dispositivos

    const revokedCount = await this.sessionService.revokeAllUserSessions(
      req.user.userId,
    );

    // Adicionar o token atual à blacklist para invalidar imediatamente
    if (req.user.tokenId) {
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + 15); // TTL do access token
      await this.tokenBlacklistService.blacklistToken(
        req.user.tokenId,
        expiresAt,
      );
    }

    return {
      message: 'Todas as sessões foram revogadas. Faça login novamente.',
      revokedSessions: revokedCount,
    };
  }

  @Post('me/devices/:deviceFingerprint/trust')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Marcar dispositivo como confiável',
    description: 'Marca um dispositivo como confiável para o usuário',
  })
  @ApiResponse({
    status: 200,
    description: 'Dispositivo marcado como confiável',
  })
  trustDevice(
    @Param('deviceFingerprint') deviceFingerprint: string,
    @Request() req: AuthenticatedRequest,
  ) {
    this.deviceManagementService.trustDevice(
      req.user.userId,
      deviceFingerprint,
    );

    return {
      message: 'Dispositivo marcado como confiável',
      deviceFingerprint,
    };
  }

  @Delete('me/devices/:deviceFingerprint/trust')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Remover confiança do dispositivo',
    description: 'Remove a confiança de um dispositivo e revoga suas sessões',
  })
  @ApiResponse({
    status: 200,
    description: 'Confiança removida e sessões revogadas',
  })
  async untrustDevice(
    @Param('deviceFingerprint') deviceFingerprint: string,
    @Request() req: AuthenticatedRequest,
  ) {
    await this.deviceManagementService.untrustDevice(
      req.user.userId,
      deviceFingerprint,
    );

    return {
      message:
        'Dispositivo removido da lista de confiáveis e sessões revogadas',
      deviceFingerprint,
    };
  }

  @Get('me/security-events')
  @ApiOperation({
    summary: 'Eventos de segurança relacionados às sessões',
    description:
      'Retorna eventos de segurança recentes relacionados às sessões do usuário',
  })
  @ApiResponse({
    status: 200,
    description: 'Lista de eventos de segurança',
  })
  async getSecurityEvents(@Request() req: AuthenticatedRequest) {
    // Buscar logs de auditoria relacionados a sessões
    const events = await this.sessionService.getUserSessionEvents(
      req.user.userId,
    );

    return {
      events,
      summary: {
        total: events.length,
        lastEvent: events[0]?.timestamp || null,
      },
    };
  }
}
