import { Module } from '@nestjs/common';
import { PasswordService } from './password.service';
import { MfaService } from './mfa.service';

@Module({
  providers: [PasswordService, MfaService],
  exports: [PasswordService, MfaService],
})
export class SecurityModule {}
