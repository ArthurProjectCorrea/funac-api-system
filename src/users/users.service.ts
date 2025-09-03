import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from '../database/prisma.service';
import { PasswordService } from '../security/password.service';
import { AuditService } from '../audit/audit.service';
import { UserStatus } from '@prisma/client';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private passwordService: PasswordService,
    private auditService: AuditService,
  ) {}

  async create(createUserDto: CreateUserDto, createdBy?: string) {
    // Verificar se email já existe
    const existingUser = await this.prisma.user.findUnique({
      where: { email: createUserDto.email.toLowerCase() },
    });

    if (existingUser) {
      throw new ConflictException('Email já está em uso');
    }

    // Hash da senha
    const passwordHash = await this.passwordService.hashPassword(
      createUserDto.password,
    );

    // Criar usuário
    const user = await this.prisma.user.create({
      data: {
        email: createUserDto.email.toLowerCase(),
        passwordHash,
        firstName: createUserDto.firstName,
        lastName: createUserDto.lastName,
        department: createUserDto.department,
        status: createUserDto.status || UserStatus.INVITED,
        createdBy,
      },
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

    // Atribuir papéis se fornecidos
    if (createUserDto.roleIds && createUserDto.roleIds.length > 0) {
      await this.assignRoles(user.id, createUserDto.roleIds, createdBy);
    }

    // Log de auditoria
    await this.auditService.log({
      actorId: createdBy,
      action: 'USER_CREATED',
      targetType: 'User',
      targetId: user.id,
      result: 'SUCCESS',
      metadata: {
        email: user.email,
        status: user.status,
        roles: createUserDto.roleIds,
      },
    });

    // Remover senha do retorno
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { passwordHash: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  async findAll(page = 1, limit = 10, search?: string, status?: UserStatus) {
    const skip = (page - 1) * limit;

    const where = {
      ...(search && {
        OR: [
          { email: { contains: search, mode: 'insensitive' as const } },
          { firstName: { contains: search, mode: 'insensitive' as const } },
          { lastName: { contains: search, mode: 'insensitive' as const } },
        ],
      }),
      ...(status && { status }),
    };

    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        skip,
        take: limit,
        include: {
          roles: {
            include: {
              role: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      data: users.map(({ passwordHash: _, ...user }) => user),
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async findOne(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
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
        sessions: {
          where: { isActive: true },
          select: {
            id: true,
            deviceFingerprint: true,
            ipAddress: true,
            userAgent: true,
            lastUsedAt: true,
            createdAt: true,
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('Usuário não encontrado');
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { passwordHash: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  async update(id: string, updateUserDto: UpdateUserDto, updatedBy?: string) {
    const user = await this.findOne(id);

    // Verificar se novo email já existe (se foi alterado)
    if (updateUserDto.email && updateUserDto.email !== user.email) {
      const existingUser = await this.prisma.user.findUnique({
        where: { email: updateUserDto.email.toLowerCase() },
      });

      if (existingUser) {
        throw new ConflictException('Email já está em uso');
      }
    }

    const updateData: Record<string, any> = {
      ...updateUserDto,
      email: updateUserDto.email?.toLowerCase(),
    };

    // Hash nova senha se fornecida
    if (updateUserDto.password) {
      updateData['passwordHash'] = await this.passwordService.hashPassword(
        updateUserDto.password,
      );
      updateData['passwordUpdatedAt'] = new Date();
      delete updateData['password'];
    }

    // Atualizar usuário
    const updatedUser = await this.prisma.user.update({
      where: { id },
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      data: updateData as any,
      include: {
        roles: {
          include: {
            role: true,
          },
        },
      },
    });

    // Atualizar papéis se fornecidos
    if (updateUserDto.roleIds) {
      await this.updateRoles(id, updateUserDto.roleIds, updatedBy);
    }

    // Log de auditoria
    await this.auditService.log({
      actorId: updatedBy,
      action: 'USER_UPDATED',
      targetType: 'User',
      targetId: id,
      result: 'SUCCESS',
      metadata: updateUserDto,
    });

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { passwordHash: _, ...userWithoutPassword } = updatedUser;
    return userWithoutPassword;
  }

  async remove(id: string, deletedBy?: string) {
    const user = await this.findOne(id);

    await this.prisma.user.delete({
      where: { id },
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: deletedBy,
      action: 'USER_DELETED',
      targetType: 'User',
      targetId: id,
      result: 'SUCCESS',
      metadata: {
        email: user.email,
        status: user.status,
      },
    });

    return { message: 'Usuário removido com sucesso' };
  }

  private async assignRoles(
    userId: string,
    roleIds: string[],
    grantedBy?: string,
  ) {
    const roleData = roleIds.map((roleId) => ({
      userId,
      roleId,
      grantedBy,
    }));

    await this.prisma.userRole.createMany({
      data: roleData,
      skipDuplicates: true,
    });
  }

  private async updateRoles(
    userId: string,
    roleIds: string[],
    grantedBy?: string,
  ) {
    // Remover papéis existentes
    await this.prisma.userRole.deleteMany({
      where: { userId },
    });

    // Adicionar novos papéis
    if (roleIds.length > 0) {
      await this.assignRoles(userId, roleIds, grantedBy);
    }
  }
}
