import { MailerService } from './../mailer/mailer.service';
import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dto/signupDto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { SigninDto } from './dto/signinDto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import * as speakeasy from 'speakeasy';
import { ResetPassswordConfirmationDto } from './dto/resetPassswordConfirmationDto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly mailerService: MailerService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}
  async signup(signupDato: SignupDto) {
    const { email, password, username } = signupDato;

    // verifier si l'utilisateur est deja inscrit
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (user) throw new ConflictException('User already exists');

    // hasher le mots de passe
    const hash = await bcrypt.hash(password, 10);

    // Enregistrer le user dans la BD
    await this.prismaService.user.create({
      data: {
        email,
        username,
        password: hash,
      },
    });

    // Envoyer un email de confirmation
    await this.mailerService.sendSignupConfirmation(email);

    // Retourner une reponse de success
    return {
      data: 'User successfuly created',
    };
  }

  async Signin(signinDto: SigninDto) {
    const { email, password } = signinDto;

    //verifier si l'utilisateur est deja inscrit
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    //comparer mots de passe
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new UnauthorizedException('password does not match');

    // retourner token 39:39
    const payload = {
      sub: user.userId,
      email: user.email,
    };
    const token = this.jwtService.sign(payload, {
      expiresIn: '2h',
      secret: this.configService.get('SECREY_KEY'),
    });
    return {
      token,
      user: {
        username: user.username,
        email: user.email,
      },
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDemandDto) {
    const { email } = resetPasswordDto;
    //verifier si l'utilisateur est deja inscrit
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    const code = speakeasy.totp({
      secret: this.configService.get('OTP_CODE'),
      digits: 5,
      step: 60 * 15,
      encoding: 'base32',
    });

    const url = 'http://localhost:3000/auth/reset-password-confirmation';
    await this.mailerService.sendResetPassword(email, url, code);
    return {
      data: 'reset password mail has been sent',
    };
  }

  async resetPassswordConfirmation(
    resetPassswordConfirmationDto: ResetPassswordConfirmationDto,
  ) {
    const { code, email, password } = resetPassswordConfirmationDto;
    //verifier si l'utilisateur est deja inscrit
    const user = await this.prismaService.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    const match = speakeasy.totp.verify({
      secret: this.configService.get('OTP_CODE'),
      token: code,
      digits: 5,
      step: 60 * 15,
      encoding: 'base32',
    });

    if(!match) throw new UnauthorizedException("invalid/expired token")
    const hash = await bcrypt.hash(password, 10)
    await this.prismaService.user.update({
      where : {email},
      data : {
        password : hash
      }
    })
    return {data: {
      data : "password updated" 
    }}
  }
}
