import { IsNotEmpty, IsString, IsEmail, MinLength } from 'class-validator';

export class createPasswordDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  readonly newPassword: string;
}
