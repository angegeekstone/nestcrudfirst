import { Body, Controller, Post } from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signinDto';
import { ResetPasswordDemandDtp } from './dto/resetPasswordDemandDto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authservice: AuthService){}
    @Post("Signup")
    signup(@Body() signupDato : SignupDto){
        return this.authservice.signup(signupDato)
    }

    @Post("SignIn")
    signin(@Body() signinDto : SigninDto) {
        return this.authservice.Signin(signinDto)
    }

    @Post('reset-password')
    resetPasswordDemand(@Body() resetPasswordDto : ResetPasswordDemandDtp){
        return  this.authservice.resetPassword(resetPasswordDto)
    }
}
