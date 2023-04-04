import {IsNotEmpty, IsEmail, } from "class-validator";

export class ResetPasswordDto{
    
    @IsEmail({},{message: 'Please enter a valid email'})
    @IsNotEmpty()
    readonly email: string;
    
} 