import { ConfigService } from '@nestjs/config';
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import {type} from 'os'
import { PrismaService } from 'src/prisma/prisma.service';

type Payload = {
    sub : number,
    email : string
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy)  {
    constructor(configService : ConfigService, private readonly prismaService : PrismaService){
        super({
            jwtFromRequest : ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrkey :configService.get("SECREY_KEY"),
            ignoreExpiration : false
        })
    }
  async validate(payload : Payload){
     const user = await this.prismaService.user.findUnique({
        where: {email : payload.email}
      })
      if (!user) throw new UnauthorizedException("Unauthorized")
      console.log(user)
    return user
  }
}