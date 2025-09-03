import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';
import { PrismaService } from '../database/prisma.service';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class RolesService {
  constructor(
    private prisma: PrismaService,
    private auditService: AuditService,
  ) {}

  async create(createRoleDto: CreateRoleDto, createdBy?: string) {
    // Verificar se nome já existe
    const existingRole = await this.prisma.role.findUnique({
      where: { name: createRoleDto.name },
    });

    if (existingRole) {
      throw new ConflictException('Nome do papel já está em uso');
    }

    // Criar papel
    const role = await this.prisma.role.create({
      data: {
        name: createRoleDto.name,
        description: createRoleDto.description,
      },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    // Atribuir permissões se fornecidas
    if (createRoleDto.permissionIds && createRoleDto.permissionIds.length > 0) {
      await this.assignPermissions(role.id, createRoleDto.permissionIds);
    }

    // Log de auditoria
    await this.auditService.log({
      actorId: createdBy,
      action: 'ROLE_CREATED',
      targetType: 'Role',
      targetId: role.id,
      result: 'SUCCESS',
      metadata: {
        name: role.name,
        permissions: createRoleDto.permissionIds,
      },
    });

    return role;
  }

  async findAll() {
    return this.prisma.role.findMany({
      include: {
        permissions: {
          include: {
            permission: true,
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
                status: true,
              },
            },
          },
        },
      },
      orderBy: { name: 'asc' },
    });
  }

  async findOne(id: string) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: {
        permissions: {
          include: {
            permission: true,
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
                status: true,
              },
            },
          },
        },
      },
    });

    if (!role) {
      throw new NotFoundException('Papel não encontrado');
    }

    return role;
  }

  async update(id: string, updateRoleDto: UpdateRoleDto, updatedBy?: string) {
    const role = await this.findOne(id);

    // Verificar se novo nome já existe (se foi alterado)
    if (updateRoleDto.name && updateRoleDto.name !== role.name) {
      const existingRole = await this.prisma.role.findUnique({
        where: { name: updateRoleDto.name },
      });

      if (existingRole) {
        throw new ConflictException('Nome do papel já está em uso');
      }
    }

    // Atualizar papel
    const updatedRole = await this.prisma.role.update({
      where: { id },
      data: {
        name: updateRoleDto.name,
        description: updateRoleDto.description,
      },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
      },
    });

    // Atualizar permissões se fornecidas
    if (updateRoleDto.permissionIds) {
      await this.updatePermissions(id, updateRoleDto.permissionIds);
    }

    // Log de auditoria
    await this.auditService.log({
      actorId: updatedBy,
      action: 'ROLE_UPDATED',
      targetType: 'Role',
      targetId: id,
      result: 'SUCCESS',
      metadata: updateRoleDto,
    });

    return updatedRole;
  }

  async remove(id: string, deletedBy?: string) {
    const role = await this.findOne(id);

    // Verificar se papel tem usuários associados
    const usersWithRole = await this.prisma.userRole.count({
      where: { roleId: id },
    });

    if (usersWithRole > 0) {
      throw new ConflictException(
        'Não é possível remover papel que possui usuários associados',
      );
    }

    await this.prisma.role.delete({
      where: { id },
    });

    // Log de auditoria
    await this.auditService.log({
      actorId: deletedBy,
      action: 'ROLE_DELETED',
      targetType: 'Role',
      targetId: id,
      result: 'SUCCESS',
      metadata: {
        name: role.name,
        description: role.description,
      },
    });

    return { message: 'Papel removido com sucesso' };
  }

  private async assignPermissions(roleId: string, permissionIds: string[]) {
    const permissionData = permissionIds.map((permissionId) => ({
      roleId,
      permissionId,
    }));

    await this.prisma.rolePermission.createMany({
      data: permissionData,
      skipDuplicates: true,
    });
  }

  private async updatePermissions(roleId: string, permissionIds: string[]) {
    // Remover permissões existentes
    await this.prisma.rolePermission.deleteMany({
      where: { roleId },
    });

    // Adicionar novas permissões
    if (permissionIds.length > 0) {
      await this.assignPermissions(roleId, permissionIds);
    }
  }
}
