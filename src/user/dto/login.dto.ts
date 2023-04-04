import {IsNotEmpty, IsString, IsEmail, MinLength} from "class-validator";

export class LoginDto{
    
    @IsEmail({},{message: 'Please enter a valid email'})
    @IsNotEmpty()
    readonly email: string;

    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    readonly password: string;
    
} 