import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database...');

  // Create permissions
  const permissions = [
    {
      name: 'user:create',
      resource: 'user',
      action: 'create',
      description: 'Create new users',
    },
    {
      name: 'user:read',
      resource: 'user',
      action: 'read',
      description: 'View user information',
    },
    {
      name: 'user:update',
      resource: 'user',
      action: 'update',
      description: 'Update user information',
    },
    {
      name: 'user:delete',
      resource: 'user',
      action: 'delete',
      description: 'Delete users',
    },
    {
      name: 'department:manage',
      resource: 'department',
      action: 'manage',
      description: 'Manage department settings',
    },
    {
      name: 'department:view',
      resource: 'department',
      action: 'view',
      description: 'View department information',
    },
    {
      name: 'report:generate',
      resource: 'report',
      action: 'generate',
      description: 'Generate reports',
    },
    {
      name: 'report:view_all',
      resource: 'report',
      action: 'view_all',
      description: 'View all reports',
    },
    {
      name: 'report:view_own',
      resource: 'report',
      action: 'view_own',
      description: 'View own reports',
    },
    {
      name: 'system:config',
      resource: 'system',
      action: 'config',
      description: 'Configure system settings',
    },
    {
      name: 'audit:view',
      resource: 'audit',
      action: 'view',
      description: 'View audit logs',
    },
  ];

  console.log('Creating permissions...');
  for (const permission of permissions) {
    await prisma.permission.upsert({
      where: { name: permission.name },
      update: {},
      create: permission,
    });
  }

  // Create roles
  console.log('Creating roles...');
  
  const systemAdminRole = await prisma.role.upsert({
    where: { name: 'system_admin' },
    update: {},
    create: {
      name: 'system_admin',
      description: 'Administrador do Sistema - controla toda a configuração da plataforma',
    },
  });

  const departmentManagerRole = await prisma.role.upsert({
    where: { name: 'department_manager' },
    update: {},
    create: {
      name: 'department_manager',
      description: 'Gestor de Departamento - gerencia usuários, relatórios e vínculos dentro do seu setor',
    },
  });

  const socialWorkerRole = await prisma.role.upsert({
    where: { name: 'social_worker' },
    update: {},
    create: {
      name: 'social_worker',
      description: 'Atendente/Assistente Social - acesso limitado a perfis de recuperandos e relatórios específicos',
    },
  });

  const externalUserRole = await prisma.role.upsert({
    where: { name: 'external_user' },
    update: {},
    create: {
      name: 'external_user',
      description: 'Usuário Externo (Recuperando/Egresso) - acesso restrito ao próprio perfil, folha de ponto, atividades e histórico',
    },
  });

  // Assign permissions to roles
  console.log('Assigning permissions to roles...');

  // System Admin - all permissions
  const allPermissions = await prisma.permission.findMany();
  for (const permission of allPermissions) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: systemAdminRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: systemAdminRole.id,
        permissionId: permission.id,
      },
    });
  }

  // Department Manager permissions
  const managerPermissions = [
    'user:read',
    'user:update',
    'department:manage',
    'department:view',
    'report:generate',
    'report:view_all',
  ];

  for (const permName of managerPermissions) {
    const permission = await prisma.permission.findUnique({
      where: { name: permName },
    });
    if (permission) {
      await prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId: departmentManagerRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: departmentManagerRole.id,
          permissionId: permission.id,
        },
      });
    }
  }

  // Social Worker permissions
  const workerPermissions = [
    'user:read',
    'department:view',
    'report:view_own',
  ];

  for (const permName of workerPermissions) {
    const permission = await prisma.permission.findUnique({
      where: { name: permName },
    });
    if (permission) {
      await prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId: socialWorkerRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: socialWorkerRole.id,
          permissionId: permission.id,
        },
      });
    }
  }

  // External User permissions (minimal)
  const externalPermissions = ['report:view_own'];

  for (const permName of externalPermissions) {
    const permission = await prisma.permission.findUnique({
      where: { name: permName },
    });
    if (permission) {
      await prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId: externalUserRole.id,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          roleId: externalUserRole.id,
          permissionId: permission.id,
        },
      });
    }
  }

  // Create default admin user
  console.log('Creating default admin user...');
  const hashedPassword = await argon2.hash('Admin123!@#', {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,
    timeCost: 3,
    parallelism: 1,
  });

  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@funac.gov.br' },
    update: {},
    create: {
      email: 'admin@funac.gov.br',
      passwordHash: hashedPassword,
      emailVerified: true,
      emailVerifiedAt: new Date(),
      status: 'ACTIVE',
      firstName: 'Administrador',
      lastName: 'Sistema',
      department: 'Tecnologia da Informação',
    },
  });

  // Assign system admin role to default user
  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: adminUser.id,
        roleId: systemAdminRole.id,
      },
    },
    update: {},
    create: {
      userId: adminUser.id,
      roleId: systemAdminRole.id,
    },
  });

  console.log('✅ Seeding completed successfully!');
  console.log('');
  console.log('🔑 Default admin credentials:');
  console.log('   Email: admin@funac.gov.br');
  console.log('   Password: Admin123!@#');
  console.log('   Role: System Admin');
  console.log('');
  console.log('⚠️  Remember to change the default password in production!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
