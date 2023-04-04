import { Body, Controller, Post, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignUpDto } from './dto/signup.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { createPasswordDto } from './dto/createPassword.dto';

@Controller('user')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  signUp(@Body() signUpDto: SignUpDto): Promise<{ token: string }> {
    return this.authService.signUp(signUpDto);
  }

  @Post('/login')
  async login(
    @Body() loginDto: LoginDto,
  ): Promise<{ token: string; message: string }> {
    
    return this.authService.login(loginDto);
  }

  @Post('/reset-password')
  resetPassword(
    @Body() ResetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.resetPassword(ResetPasswordDto);
  }

  @Post('/create-password/:email')
  createPassword(
    @Param() params: Record<string, string>,
    @Body() createPasswordDto: createPasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.createPassword(createPasswordDto, params);
  }
}
