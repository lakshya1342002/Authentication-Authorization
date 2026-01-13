import { Request , Response } from "express";
import { registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { hashPassword } from "../../lib/hash";
import  jwt  from "jsonwebtoken";
import { sendEmail } from "../../lib/email";

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
            twoFactorEnabled : false
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

     const verifyUrl = `${getAppUrl}/auth/verify-email?token=${verifyToken}`;

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