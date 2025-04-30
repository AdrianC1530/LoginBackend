// src/users/users.controller.ts
import { Controller, Get, Delete, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBearerAuth } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { User } from './schemas/user.schema';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

@ApiTags('Users')
@Controller('users')
@UseGuards(JwtAuthGuard) // Aplicar el guard a todas las rutas
@ApiBearerAuth('access-token') // Usar el mismo nombre que definimos en main.ts
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // Endpoint para obtener un usuario por nombre de usuario
  @Get('username/:username')
  @ApiOperation({ summary: 'Get user by username' })
  @ApiParam({ name: 'username', description: 'Username of the user' })
  @ApiResponse({
    status: 200,
    description: 'User found',
    schema: {
      properties: {
        _id: { type: 'string', example: '6070f1f0b5d7c31b50e93ec1' },
        username: { type: 'string', example: 'john_doe' },
        email: { type: 'string', example: 'john@example.com' },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async getUserByUsername(@Param('username') username: string): Promise<User | null> {
    return this.usersService.findByUsername(username);
  }

  // Endpoint para eliminar un usuario por correo
  @Delete('email/:email')
  @ApiOperation({ summary: 'Delete user by email' })
  @ApiParam({ name: 'email', description: 'Email of the user to delete' })
  @ApiResponse({
    status: 200,
    description: 'User successfully deleted',
    schema: {
      properties: {
        message: { type: 'string', example: 'User successfully deleted' },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async deleteUserByEmail(@Param('email') email: string) {
    return this.usersService.removeByEmail(email);
  }
}