import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateSessionDto } from './dto/create-session.dto';
import { UpdateSessionDto } from './dto/update-session.dto';
import { PrismaService } from '../database/prisma.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class SessionsService {
  constructor(
    private prisma: PrismaService,
    private auditService: AuditService,
  ) {}

  async findAll(page = 1, limit = 10, userId?: string) {
    const skip = (page - 1) * limit;

    const where = {
      isActive: true,
      ...(userId && { userId }),
    };

    const [sessions, total] = await Promise.all([
      this.prisma.session.findMany({
        where,
        skip,
        take: limit,
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
        orderBy: { lastUsedAt: 'desc' },
      }),
      this.prisma.session.count({ where }),
    ]);

    return {
      data: sessions,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async findOne(id: string) {
    const session = await this.prisma.session.findUnique({
      where: { id },
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
    });

    if (!session) {
      throw new NotFoundException('Sessão não encontrada');
    }

    return session;
  }

  async revoke(id: string, revokedBy?: string) {
    const session = await this.findOne(id);

    await this.prisma.session.update({
      where: { id },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: revokedBy,
      action: 'SESSION_REVOKED',
      targetType: 'Session',
      targetId: id,
      result: 'SUCCESS',
      metadata: {
        userId: session.userId,
        userEmail: session.user.email,
        ipAddress: session.ipAddress,
      },
    });

    return { message: 'Sessão revogada com sucesso' };
  }

  async revokeAllUserSessions(userId: string, revokedBy?: string) {
    const revokedCount = await this.prisma.session.updateMany({
      where: {
        userId,
        isActive: true,
      },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: revokedBy,
      action: 'ALL_SESSIONS_REVOKED',
      targetType: 'User',
      targetId: userId,
      result: 'SUCCESS',
      metadata: {
        revokedCount: revokedCount.count,
      },
    });

    return {
      message: 'Todas as sessões do usuário foram revogadas',
      revokedCount: revokedCount.count,
    };
  }

  async getActiveSessionsCount(userId: string): Promise<number> {
    return this.prisma.session.count({
      where: {
        userId,
        isActive: true,
      },
    });
  }

  async cleanupExpiredSessions(): Promise<number> {
    const result = await this.prisma.session.updateMany({
      where: {
        isActive: true,
        expiresAt: {
          lt: new Date(),
        },
      },
      data: {
        isActive: false,
        revokedAt: new Date(),
      },
    });

    return result.count;
  }

  // Métodos originais mantidos para compatibilidade
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  create(_: CreateSessionDto) {
    return 'This action adds a new session';
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  update(id: number, _: UpdateSessionDto) {
    return `This action updates a #${id} session`;
  }

  remove(id: number) {
    return `This action removes a #${id} session`;
  }
}
