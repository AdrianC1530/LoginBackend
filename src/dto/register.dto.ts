// dto/register.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @ApiProperty({
    example: 'usuario1',
    description: 'Nombre de usuario',
    required: true
  })
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({
    example: 'contraseña123',
    description: 'Contraseña del usuario',
    required: true
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  password: string;

  @ApiProperty({
    example: 'Juan Pérez',
    description: 'Nombre completo del usuario',
    required: true
  })
  @IsString()
  @IsNotEmpty()
  nombre: string;

  @ApiProperty({
    example: 'juan@ejemplo.com',
    description: 'Correo electrónico del usuario',
    required: true
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}