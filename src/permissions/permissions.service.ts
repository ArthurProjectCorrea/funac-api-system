import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { CreatePermissionDto } from './dto/create-permission.dto';
import { UpdatePermissionDto } from './dto/update-permission.dto';
import { PrismaService } from '../database/prisma.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class PermissionsService {
  constructor(
    private prisma: PrismaService,
    private auditService: AuditService,
  ) {}

  async create(createPermissionDto: CreatePermissionDto, createdBy?: string) {
    // Verificar se nome já existe
    const existingPermission = await this.prisma.permission.findUnique({
      where: { name: createPermissionDto.name },
    });

    if (existingPermission) {
      throw new ConflictException('Nome da permissão já está em uso');
    }

    // Criar permissão
    const permission = await this.prisma.permission.create({
      data: createPermissionDto,
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: createdBy,
      action: 'PERMISSION_CREATED',
      targetType: 'Permission',
      targetId: permission.id,
      result: 'SUCCESS',
      metadata: {
        name: permission.name,
        resource: permission.resource,
        action: permission.action,
      },
    });

    return permission;
  }

  async findAll() {
    return this.prisma.permission.findMany({
      include: {
        roles: {
          include: {
            role: {
              select: {
                id: true,
                name: true,
                description: true,
              },
            },
          },
        },
        users: {
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
        },
      },
      orderBy: [{ resource: 'asc' }, { action: 'asc' }],
    });
  }

  async findOne(id: string) {
    const permission = await this.prisma.permission.findUnique({
      where: { id },
      include: {
        roles: {
          include: {
            role: {
              select: {
                id: true,
                name: true,
                description: true,
              },
            },
          },
        },
        users: {
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
        },
      },
    });

    if (!permission) {
      throw new NotFoundException('Permissão não encontrada');
    }

    return permission;
  }

  async update(
    id: string,
    updatePermissionDto: UpdatePermissionDto,
    updatedBy?: string,
  ) {
    const permission = await this.findOne(id);

    // Verificar se novo nome já existe (se foi alterado)
    if (
      updatePermissionDto.name &&
      updatePermissionDto.name !== permission.name
    ) {
      const existingPermission = await this.prisma.permission.findUnique({
        where: { name: updatePermissionDto.name },
      });

      if (existingPermission) {
        throw new ConflictException('Nome da permissão já está em uso');
      }
    }

    // Atualizar permissão
    const updatedPermission = await this.prisma.permission.update({
      where: { id },
      data: updatePermissionDto,
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: updatedBy,
      action: 'PERMISSION_UPDATED',
      targetType: 'Permission',
      targetId: id,
      result: 'SUCCESS',
      metadata: updatePermissionDto,
    });

    return updatedPermission;
  }

  async remove(id: string, deletedBy?: string) {
    const permission = await this.findOne(id);

    // Verificar se permissão tem papéis associados
    const rolesWithPermission = await this.prisma.rolePermission.count({
      where: { permissionId: id },
    });

    if (rolesWithPermission > 0) {
      throw new ConflictException(
        'Não é possível remover permissão que está associada a papéis',
      );
    }

    await this.prisma.permission.delete({
      where: { id },
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: deletedBy,
      action: 'PERMISSION_DELETED',
      targetType: 'Permission',
      targetId: id,
      result: 'SUCCESS',
      metadata: {
        name: permission.name,
        resource: permission.resource,
        action: permission.action,
      },
    });

    return { message: 'Permissão removida com sucesso' };
  }
}
