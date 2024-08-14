import { IsEmail, IsNotEmpty } from "class-validator"

export class ResetPasswordDemandDtp {
    @IsEmail()
    readonly email : string 
}