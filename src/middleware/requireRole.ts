import { NextFunction , Response ,Request } from "express";




function requireRole(role: 'user' | 'admin'){

    return (req:Request , res: Response , next : NextFunction) =>{
        const authReq = res as any;
        const authUser = authReq.user;

    if(!authUser){
         return res.status(401).json({
            message:'You are not auth user ! you cant enter the building'
        })
    }

    if(authUser.role !== role){
        return res.status(403).json({
            message:'You dont have correct role to access'
        })
    }
     
    next();

    };
}

export default requireRole;