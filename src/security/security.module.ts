import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PasswordService } from './password.service';
import { MfaService } from './mfa.service';

@Module({
  imports: [ConfigModule],
  providers: [PasswordService, MfaService],
  exports: [PasswordService, MfaService],
})
export class SecurityModule {}
