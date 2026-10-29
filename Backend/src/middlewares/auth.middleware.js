const jwt= require("jsonwebtoken")
const blacklistTokenModel= require("../models/blacklist.model") 

async function authUserMiddleware(req, res, next){
    const token= req.cookies.token

    if(!token){
        return res.status(401).json({message: "Unauthorized access, please login"})
    }

    const isTokenBlacklisted= await blacklistTokenModel.findOne({token: token})

    if(isTokenBlacklisted){
        return res.status(401).json({message: "Token is blacklisted, please login again"})
    }

    try{
        const decoded= jwt.verify(token, process.env.JWT_SECRET)
        req.user= decoded
        next()
    }catch(err){
        return res.status(401).json({message: "Invalid token, please login again"})
    }
}

module.exports= { authUserMiddleware } 