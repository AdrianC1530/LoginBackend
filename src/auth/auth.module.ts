// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule.register({ defaultStrategy: 'jwt' }), // Registro explícito de la estrategia
    JwtModule.register({
      secret: 'mi-clave-secreta',
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy], // Asegúrate de que JwtStrategy esté aquí
  exports: [AuthService, JwtStrategy], // Exporta la estrategia si necesitas usarla en otros módulos
})
export class AuthModule {}