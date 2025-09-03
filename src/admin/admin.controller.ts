import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseGuards,
  Request,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { AdminService } from './admin.service';
import { JwtAuthGuard } from '../auth/guards/auth.guards';
import { UsersService } from '../users/users.service';
import { RolesService } from '../roles/roles.service';
import { PermissionsService } from '../permissions/permissions.service';
import { SessionsService } from '../sessions/sessions.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { UpdateUserDto } from '../users/dto/update-user.dto';
import { CreateRoleDto } from '../roles/dto/create-role.dto';
import { UpdateRoleDto } from '../roles/dto/update-role.dto';
import { UserStatus } from '@prisma/client';

interface AuthenticatedRequest {
  user: {
    userId: string;
    email: string;
    roles: string[];
    permissions: string[];
  };
}

@ApiTags('Admin')
@ApiBearerAuth('JWT-auth')
@Controller('admin')
@UseGuards(JwtAuthGuard)
export class AdminController {
  constructor(
    private readonly adminService: AdminService,
    private readonly usersService: UsersService,
    private readonly rolesService: RolesService,
    private readonly permissionsService: PermissionsService,
    private readonly sessionsService: SessionsService,
  ) {}

  // === USUÁRIOS ===
  @Get('users')
  @ApiOperation({
    summary: 'Listar usuários (Admin)',
    description: 'Lista todos os usuários do sistema com filtros avançados',
  })
  @ApiQuery({ name: 'page', required: false, description: 'Página' })
  @ApiQuery({ name: 'limit', required: false, description: 'Itens por página' })
  @ApiQuery({
    name: 'search',
    required: false,
    description: 'Buscar por nome ou email',
  })
  @ApiQuery({ name: 'status', required: false, enum: UserStatus })
  @ApiResponse({ status: 200, description: 'Lista de usuários' })
  async getUsers(
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('search') search?: string,
    @Query('status') status?: UserStatus,
  ) {
    return this.usersService.findAll(+page, +limit, search, status);
  }

  @Post('users')
  async createUser(
    @Body() createUserDto: CreateUserDto,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.usersService.create(createUserDto, req.user.userId);
  }

  @Get('users/:id')
  async getUser(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Patch('users/:id')
  async updateUser(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.usersService.update(id, updateUserDto, req.user.userId);
  }

  @Delete('users/:id')
  async deleteUser(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.usersService.remove(id, req.user.userId);
  }

  @Patch('users/:id/status')
  async updateUserStatus(
    @Param('id') id: string,
    @Body('status') status: UserStatus,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.usersService.update(id, { status }, req.user.userId);
  }

  @Post('users/invite')
  async inviteUser(
    @Body() inviteData: { email: string; roleIds?: string[] },
    @Request() req: AuthenticatedRequest,
  ) {
    return this.adminService.inviteUser(inviteData, req.user.userId);
  }

  // === PAPÉIS ===
  @Get('roles')
  async getRoles() {
    return this.rolesService.findAll();
  }

  @Post('roles')
  async createRole(
    @Body() createRoleDto: CreateRoleDto,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.rolesService.create(createRoleDto, req.user.userId);
  }

  @Get('roles/:id')
  async getRole(@Param('id') id: string) {
    return this.rolesService.findOne(id);
  }

  @Patch('roles/:id')
  async updateRole(
    @Param('id') id: string,
    @Body() updateRoleDto: UpdateRoleDto,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.rolesService.update(id, updateRoleDto, req.user.userId);
  }

  @Delete('roles/:id')
  async deleteRole(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.rolesService.remove(id, req.user.userId);
  }

  // === PERMISSÕES ===
  @Get('permissions')
  async getPermissions() {
    return this.permissionsService.findAll();
  }

  // === SESSÕES ===
  @Get('sessions')
  async getSessions(
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('userId') userId?: string,
  ) {
    return this.sessionsService.findAll(+page, +limit, userId);
  }

  @Delete('sessions/:id')
  async revokeSession(
    @Param('id') id: string,
    @Request() req: AuthenticatedRequest,
  ) {
    return this.sessionsService.revoke(id, req.user.userId);
  }

  // === DASHBOARD ===
  @Get('dashboard/stats')
  async getDashboardStats() {
    return this.adminService.getDashboardStats();
  }

  // === AUDITORIA ===
  @Get('audit')
  async getAuditLogs(
    @Query('page') page = 1,
    @Query('limit') limit = 10,
    @Query('action') action?: string,
    @Query('actorId') actorId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ) {
    return this.adminService.getAuditLogs({
      page: +page,
      limit: +limit,
      action,
      actorId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
    });
  }
}
