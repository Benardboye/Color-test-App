import {IsNotEmpty, IsString, IsEmail, MinLength} from "class-validator";

export class SignUpDto{
    @IsString()
    @IsNotEmpty()
    readonly userName: string;

    @IsEmail({},{message: 'Please enter a valid email'})
    @IsNotEmpty()
    readonly email: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    readonly password: string;
} 