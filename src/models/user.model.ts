import { Schema , model } from "mongoose";
import { unwatchFile } from "node:fs";
import { string } from "zod";
import { de } from "zod/locales";
import { lowercase, required } from "zod/mini";


const userSchema = new Schema({
    email:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true
    },
    passwordHash:{
        type:String,
        required:true
    },
     role:{
        type:String,
        enum:['user' , 'admin'],
        default: "user",
    },
    isEmailVerified:{
        type:Boolean,
        default:true
    },
    name:{
        type:String
    },
    twoFactorEnabled:{
        type: Boolean,
        default : false
    },
    twoFactorSecret:{
        type:String,
        default:undefined
    },
    tokenVersion:{
        type:Number,
        default:0
    },
    resetPasswordToken:{
        type:String,
        default:undefined
    },
    resetPasswordExpires:{
        type:Date,
        default: undefined
    }
} ,
{
    timestamps: true
});


export const User = model("User" , userSchema);
