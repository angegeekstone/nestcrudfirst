import { Body, Controller, Delete, Post, UseGuards } from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signinDto';
import { ResetPassswordConfirmationDto,} from './dto/resetPassswordConfirmationDto';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { AuthGuard } from '@nestjs/passport';

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
    resetPasswordDemand(@Body() resetPasswordDto : ResetPasswordDemandDto){
        return  this.authservice.resetPassword(resetPasswordDto)
    }

    @Post('rest-password-confirmation')
    resetPassswordConfirmation(@Body() resetPassswordConfirmationDto : ResetPassswordConfirmationDto){
        return this.authservice.resetPassswordConfirmation(resetPassswordConfirmationDto)
    }

   /*  @UseGuards(AuthGuard('jwt'))
    @Delete('delete')
    deleteAccount(){
        return 'Account delete'
    } */
}
