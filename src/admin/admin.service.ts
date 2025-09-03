import { Injectable } from '@nestjs/common';
import { CreateAdminDto } from './dto/create-admin.dto';
import { UpdateAdminDto } from './dto/update-admin.dto';
import { PrismaService } from '../database/prisma.service';
import { AuditService } from '../audit/audit.service';
import { TokenService } from '../auth/services/token.service';
import { PasswordService } from '../security/password.service';
import { UserStatus, TokenType } from '@prisma/client';

interface InviteUserData {
  email: string;
  roleIds?: string[];
}

interface AuditFilters {
  page: number;
  limit: number;
  action?: string;
  actorId?: string;
  startDate?: Date;
  endDate?: Date;
}

@Injectable()
export class AdminService {
  constructor(
    private prisma: PrismaService,
    private auditService: AuditService,
    private tokenService: TokenService,
    private passwordService: PasswordService,
  ) {}

  async inviteUser(inviteData: InviteUserData, invitedBy: string) {
    // Verificar se email já existe
    const existingUser = await this.prisma.user.findUnique({
      where: { email: inviteData.email.toLowerCase() },
    });

    if (existingUser) {
      return { message: 'Convite enviado com sucesso' }; // Não revelar se email existe
    }

    // Gerar senha temporária
    const tempPassword = this.generateTempPassword();
    const passwordHash = await this.passwordService.hashPassword(tempPassword);

    // Criar usuário com status INVITED
    const user = await this.prisma.user.create({
      data: {
        email: inviteData.email.toLowerCase(),
        passwordHash,
        status: UserStatus.INVITED,
        createdBy: invitedBy,
      },
    });

    // Atribuir papéis se fornecidos
    if (inviteData.roleIds && inviteData.roleIds.length > 0) {
      const roleData = inviteData.roleIds.map((roleId) => ({
        userId: user.id,
        roleId,
        grantedBy: invitedBy,
      }));

      await this.prisma.userRole.createMany({
        data: roleData,
      });
    }

    // Criar token de convite
    await this.tokenService.createToken(user.id, TokenType.INVITATION, {
      tempPassword,
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: invitedBy,
      action: 'USER_INVITED',
      targetType: 'User',
      targetId: user.id,
      result: 'SUCCESS',
      metadata: {
        email: user.email,
        roles: inviteData.roleIds,
      },
    });

    return {
      message: 'Convite enviado com sucesso',
      userId: user.id,
      tempPassword, // Em produção, enviar por email
    };
  }

  async getDashboardStats() {
    const [
      totalUsers,
      activeUsers,
      invitedUsers,
      totalRoles,
      totalPermissions,
      activeSessions,
      recentAudits,
    ] = await Promise.all([
      this.prisma.user.count(),
      this.prisma.user.count({ where: { status: UserStatus.ACTIVE } }),
      this.prisma.user.count({ where: { status: UserStatus.INVITED } }),
      this.prisma.role.count(),
      this.prisma.permission.count(),
      this.prisma.session.count({ where: { isActive: true } }),
      this.prisma.auditLog.count({
        where: {
          timestamp: {
            gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Últimas 24h
          },
        },
      }),
    ]);

    // Estatísticas por status de usuário
    const usersByStatus = await this.prisma.user.groupBy({
      by: ['status'],
      _count: {
        status: true,
      },
    });

    // Logins nas últimas 24h
    const recentLogins = await this.prisma.auditLog.count({
      where: {
        action: 'LOGIN_SUCCESS',
        timestamp: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
        },
      },
    });

    return {
      users: {
        total: totalUsers,
        active: activeUsers,
        invited: invitedUsers,
        byStatus: usersByStatus.reduce(
          (acc, curr) => {
            acc[curr.status] = curr._count.status;
            return acc;
          },
          {} as Record<string, number>,
        ),
      },
      system: {
        totalRoles,
        totalPermissions,
        activeSessions,
      },
      activity: {
        recentLogins,
        recentAudits,
      },
    };
  }

  async getAuditLogs(filters: AuditFilters) {
    const { page, limit, action, actorId, startDate, endDate } = filters;
    const skip = (page - 1) * limit;

    const where = {
      ...(action && { action }),
      ...(actorId && { actorId }),
      ...((startDate || endDate) && {
        timestamp: {
          ...(startDate && { gte: startDate }),
          ...(endDate && { lte: endDate }),
        },
      }),
    };

    const [logs, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        skip,
        take: limit,
        include: {
          actor: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
            },
          },
          target: {
            select: {
              id: true,
              email: true,
              firstName: true,
              lastName: true,
            },
          },
        },
        orderBy: { timestamp: 'desc' },
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return {
      data: logs,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  private generateTempPassword(): string {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  }

  // Métodos originais mantidos para compatibilidade
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  create(_: CreateAdminDto) {
    return 'This action adds a new admin';
  }

  findAll() {
    return `This action returns all admin`;
  }

  findOne(id: number) {
    return `This action returns a #${id} admin`;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  update(id: number, _: UpdateAdminDto) {
    return `This action updates a #${id} admin`;
  }

  remove(id: number) {
    return `This action removes a #${id} admin`;
  }
}
