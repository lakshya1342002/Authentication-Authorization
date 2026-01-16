import { Request , Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { checkPassword, hashPassword } from "../../lib/hash";
import  jwt  from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import { createAccessToken, createRefreshToken, verifyRefreshToken } from "../../lib/token";

function getAppUrl(){
    return process.env.APP_URL || `http://localhost:${process.env.PORT}`
}

export async function registerHandler(req:Request , res:Response){
    try{
        const result = registerSchema.safeParse(req.body);
        
        if(!result.success){
            return res.status(400).json({
                message: 'Invalid data!' , errors: result.error.flatten()
            })
        }

        const {name , email , password} = result.data;
        const normalizedEmail = email.toLowerCase().trim();

        const existingUser = await User.findOne({email:normalizedEmail});

        if(existingUser){
            return res.status(409).json({
                message:"Email is already in use! Please try with a different email",
            });
        }
         const passwordHash = await hashPassword(password);
        
         const newlyCreatedUser = await User.create({
            email:normalizedEmail,
            passwordHash,
            role:'user',
            isEmailVerified: false , 
            twoFactorEnabled : false,
            name
         })

    //email verification part

     const verifyToken = jwt.sign(
        {
            sub: newlyCreatedUser.id
        },
        process.env.JWT_ACCESS_SECRET!,
        {
            expiresIn: '1d'
        }
     )

     const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

     await sendEmail(
        newlyCreatedUser.email,
        "Verify your email",
        `<p>Please verify the email by clicking this link:</p>
         <p><a href="${verifyUrl}">${verifyUrl}</a></p>
        `
     );
     return res.status(201).json({
        message:'User registered',
        user:{
            id: newlyCreatedUser.id,
            email: newlyCreatedUser.email,
            role: newlyCreatedUser.role,
            isEmailVerified: newlyCreatedUser.isEmailVerified
        }
     })

    }catch(err){
        console.log(err);
        return res.status(500).json({
            message:'Internal server error'
        })
        
    }
}

export async function verifyEmailHandler(req: Request , res: Response){
    const token = req.query.token as string | undefined;

    if(!token){
        return res.status(400).json({
            message: ' verfication token is missing'
        })
    }
    try{
        const payload = jwt.verify(token , process.env.JWT_ACCESS_SECRET!) as {
            sub:string;
        }
        const user = await User.findById(payload.sub);

        if(!user){
            return res.status(400).json({
                message: 'User not found'
            })
        }

        if(user.isEmailVerified){
            return res.json({message: 'Email is already verified'})
        }

        user.isEmailVerified = true;
        await user.save();

         return res.json({message: 'Email is now verified! you can login'})

    }catch(err){
        console.log(err);
        return res.status(500).json({
        message:'Internal server error'
        }) 
    }
}

export async function loginHandler(req:Request , res:Response){
    try{
        const result = loginSchema.safeParse(req.body);
        
        if(!result.success){
            return res.status(400).json({
                message: 'Invalid data!' , errors: result.error.flatten()
            })
        }

        const {email , password} = result.data;
                const normalizedEmail = email.toLowerCase().trim();

                const user = await User.findOne({email:normalizedEmail});

                if(!user){
                    return res.status(400).json({message: 'Invalid email and password'})
                }

                const ok = await checkPassword(password , user.passwordHash);

                if(!ok){
                    return res.status(400).json({message: 'Invalid password'})
                }
                if(!user.isEmailVerified){
                    return res.status(400).json({message: 'Please verify your email before loggin in...'});  
                }
                
                const accessToken = createAccessToken(
                    user.id,
                    user.role,
                    user.tokenVersion
                )
                
                const refreshToken = createRefreshToken(user.id , user.tokenVersion)

                const isProd = process.env.NODE_ENV==='production';

                res.cookie("refreshToken" , refreshToken , {
                    httpOnly:true,
                    secure:isProd,
                    sameSite: 'lax',
                    maxAge: 7*24*60*60*1000
                })

                return res.status(200).json({
                    message: 'Login Successfully done',
                    accessToken,
                    user:{
                        id:user.id,
                        email:user.email,
                        role: user.role,
                        isEmailVerified: user.isEmailVerified,
                        twoFactorEnabled : user.twoFactorEnabled,
                    }
                })

    }catch(err){
            console.log(err);
                    return res.status(500).json({
                        message:'Internal server error'
                    });
                }
}

export async function refreshHandler(req:Request , res:Response){
    try{
        const token = req.cookies?.refreshToken as string | undefined;
        
        if(!token){
            return res.status(401).json({message: 'Refresh token missing'})
        }
        
        const payload = verifyRefreshToken(token)

        const user = await User.findById(payload.sub);

        if(!user){
            return res.status(401).json({message: 'User not found'})
        }
        
        if(user.tokenVersion !== payload.tokenVersion){
            return res.status(401).json({message: 'Refresh token invalidated'})
        }

        const newAccessToken = createAccessToken(
            user.id,
            user.role,
            user.tokenVersion
        )

        const newRefreshToken = createRefreshToken(user.id , user.tokenVersion)

        const isProd = process.env.NODE_ENV==='production';

                res.cookie("refreshToken" , newRefreshToken , {
                    httpOnly:true,
                    secure:isProd,
                    sameSite: 'lax',
                    maxAge: 7*24*60*60*1000
                })

                return res.status(200).json({
                    message: 'Token refreshed successfully',
                    accessToken : newAccessToken,
                    user:{
                        id:user.id,
                        email:user.email,
                        role: user.role,
                        isEmailVerified: user.isEmailVerified,
                        twoFactorEnabled : user.twoFactorEnabled,
                    }
                })

    }catch(err){
        console.log(err);
            return res.status(500).json({
             message:'Internal server error'
         });
                
    }
}

export async function logoutHandler(_req:Request , res:Response){
    res.clearCookie("refreshToken" , {path: '/'})

    return res.status(200).json({
        message:"Logged out",
    })
}