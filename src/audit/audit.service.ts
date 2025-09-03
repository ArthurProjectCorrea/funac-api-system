import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service';
import { AuditResult, Prisma } from '@prisma/client';

export interface CreateAuditLogDto {
  actorId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  result: AuditResult;
  reason?: string;
  metadata?: any;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class AuditService {
  constructor(private prisma: PrismaService) {}

  /**
   * Create an audit log entry
   */
  async log(data: CreateAuditLogDto): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data,
      });
    } catch (error) {
      // Log to console as fallback - in production should use proper logging
      console.error('Failed to create audit log:', error);
    }
  }

  /**
   * Get audit logs with filtering
   */
  async getAuditLogs(filters: {
    actorId?: string;
    action?: string;
    targetType?: string;
    targetId?: string;
    result?: AuditResult;
    startDate?: Date;
    endDate?: Date;
    page?: number;
    limit?: number;
  }) {
    const {
      actorId,
      action,
      targetType,
      targetId,
      result,
      startDate,
      endDate,
      page = 1,
      limit = 50,
    } = filters;

    const skip = (page - 1) * limit;

    const where: Prisma.AuditLogWhereInput = {};

    if (actorId) where.actorId = actorId;
    if (action) where.action = { contains: action, mode: 'insensitive' };
    if (targetType) where.targetType = targetType;
    if (targetId) where.targetId = targetId;
    if (result) where.result = result;
    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) where.timestamp.gte = startDate;
      if (endDate) where.timestamp.lte = endDate;
    }

    const [logs, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        include: {
          actor: {
            select: {
              id: true,
              email: true,
            },
          },
          target: {
            select: {
              id: true,
              email: true,
            },
          },
        },
        orderBy: { timestamp: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return {
      data: logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    };
  }
}
