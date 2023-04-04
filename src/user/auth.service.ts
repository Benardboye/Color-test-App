import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schema/user.schema';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { createPasswordDto } from './dto/createPassword.dto';
import { mailsent, resetPasswordmailHtml } from 'src/utils';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signUp(signUpDto: SignUpDto): Promise<{ token: string }> {
    const { userName, email, password } = signUpDto;

    //check if email already exists
    const userWithEmail = await this.userModel.findOne({ email });
    if (userWithEmail) {
      throw new UnauthorizedException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userModel.create({
      userName,
      email,
      password: hashedPassword,
    });

    const token = this.jwtService.sign({ id: user._id });

    return { token };
  }

  async login(loginDto: LoginDto): Promise<{ token: string; message: string }> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    const isPasswordValid =
      user && (await bcrypt.compare(password, user.password));

    if (!user || !isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const token = this.jwtService.sign({ id: user._id });

    const message = 'Login successful';

    return { token, message };
  }

  async resetPassword(
    ResetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    const { email } = ResetPasswordDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException(`Email does not exist, please signup`);
    }

    const html = resetPasswordmailHtml(email);
    await mailsent(process.env.FromAdminMail, email, 'Reset Password', html);

    const message = 'New password link sent to your email';

    return { message };
  }

  async createPassword(
    createPasswordDto: createPasswordDto,
    params: Record<string, string>,
  ): Promise<{ message: string }> {
    const { newPassword } = createPasswordDto;
    const { email } = params;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException(`User does not exist, please signup`);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await this.userModel.findOneAndUpdate(
      { email },
      {
        password: hashedPassword,
      },
    );

    const message = 'Your password has been successfully changed!';

    return { message };
  }
}
