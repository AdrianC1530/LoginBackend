import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsEmail, MinLength, MaxLength } from 'class-validator';

export class CreateUserDto {
  @ApiProperty({ 
    description: 'Username for the account', 
    example: 'john_doe' 
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  @MaxLength(20)
  username: string;

  @ApiProperty({ 
    description: 'Email address', 
    example: 'john@example.com' 
  })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({ 
    description: 'Password for the account', 
    example: 'password123',
    minLength: 6,
    maxLength: 20
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @MaxLength(20)
  password: string;
}