import { IsEmail, IsNotEmpty } from "class-validator"

export class ResetPassswordConfirmationDto {
    @IsEmail()
    readonly email : string 
    
    @IsNotEmpty()
    readonly password : string

    @IsNotEmpty()
    readonly code : string

}