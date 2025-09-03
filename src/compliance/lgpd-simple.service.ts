import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { AuditService } from '../audit/audit.service';
import { AuditResult } from '@prisma/client';
import { ComplianceRequestType, RequestStatus } from './dto';

export interface UserDataExport {
  personalData: any;
  auditTrail: any[];
  sessions: any[];
  exportedAt: Date;
  exportId: string;
}

@Injectable()
export class LgpdService {
  constructor(
    private prisma: PrismaService,
    private auditService: AuditService,
  ) {}

  /**
   * Criar solicitação LGPD
   */
  async createComplianceRequest(
    userId: string,
    type: ComplianceRequestType,
    justification?: string,
  ): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    const request = await this.prisma.complianceRequest.create({
      data: {
        userId,
        type,
        status: RequestStatus.PENDING,
        data: {
          justification,
          requestedAt: new Date(),
        },
      },
    });

    // Auditar criação
    await this.auditService.log({
      actorId: userId,
      action: 'COMPLIANCE_REQUEST_CREATED',
      targetType: 'ComplianceRequest',
      targetId: request.id,
      result: AuditResult.SUCCESS,
      metadata: { type },
    });

    return request;
  }

  /**
   * Processar solicitação de acesso aos dados
   */
  async processDataAccessRequest(requestId: string): Promise<UserDataExport> {
    const request = await this.prisma.complianceRequest.findUnique({
      where: { id: requestId },
      include: { user: true },
    });

    if (!request) {
      throw new NotFoundException('Solicitação não encontrada');
    }

    // Coletar dados básicos do usuário
    const exportData: UserDataExport = {
      personalData: {
        id: request.user.id,
        email: request.user.email,
        firstName: request.user.firstName,
        lastName: request.user.lastName,
        createdAt: request.user.createdAt,
      },
      auditTrail: [],
      sessions: [],
      exportedAt: new Date(),
      exportId: `export-${Date.now()}`,
    };

    // Marcar como concluída
    await this.prisma.complianceRequest.update({
      where: { id: requestId },
      data: {
        status: RequestStatus.COMPLETED,
        completedAt: new Date(),
      },
    });

    return exportData;
  }

  /**
   * Listar solicitações
   */
  async getComplianceRequests(userId?: string): Promise<any[]> {
    return this.prisma.complianceRequest.findMany({
      where: userId ? { userId } : undefined,
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
      },
      orderBy: { requestedAt: 'desc' },
    });
  }

  /**
   * Obter estatísticas básicas
   */
  async getComplianceStats() {
    const [total, pending] = await Promise.all([
      this.prisma.complianceRequest.count(),
      this.prisma.complianceRequest.count({
        where: { status: RequestStatus.PENDING },
      }),
    ]);

    return {
      totalRequests: total,
      pendingRequests: pending,
      complianceScore:
        pending === 0 ? 100 : Math.round(((total - pending) / total) * 100),
    };
  }
}
