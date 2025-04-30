// src/auth/auth.controller.ts
import { Controller, Post, Body, UnauthorizedException, HttpCode, UseGuards, HttpException, HttpStatus } from '@nestjs/common';
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse,
  ApiBearerAuth
} from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { LoginDto } from '../dto/login.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { UsersService } from '../users/users.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  @Post('register')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ 
    status: 201, 
    description: 'User registered successfully',
    schema: {
      properties: {
        message: { type: 'string', example: 'User registered successfully' },
        user: {
          type: 'object',
          properties: {
            _id: { type: 'string', example: '6070f1f0b5d7c31b50e93ec1' },
            username: { type: 'string', example: 'john_doe' },
            email: { type: 'string', example: 'john@example.com' }
          }
        }
      }
    }
  })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 409, description: 'Username or email already exists' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async register(@Body() createUserDto: CreateUserDto) {
    try {
      return await this.authService.register(createUserDto);
    } catch (error) {
      throw new HttpException(
        error.message || 'Error en el registro',
        error.status || HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'User login' })
  @ApiResponse({ 
    status: 200, 
    description: 'Login successful',
    schema: {
      properties: {
        access_token: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
        refresh_token: { type: 'string', example: 'abc123xyz456...' }
      }
    }
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 500, description: 'Internal server error' })
  async login(@Body() loginDto: LoginDto) {
    try {
      const user = await this.authService.validateUser(loginDto.username, loginDto.password);
      
      if (!user) {
        throw new UnauthorizedException('Credenciales inválidas');
      }
      
      return await this.authService.login(user);
    } catch (error) {
      throw new HttpException(
        error.message || 'Error en el inicio de sesión',
        error.status || HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
}