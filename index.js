import express from 'express'
import * as yup from 'yup'
import bcrypt from 'bcryptjs'
import {  v4 as uuidv4 } from "uuid"
import jwt from 'jsonwebtoken'


const app = express()
const port = 3000

let usersDb = []
const SALT = 8

const config = {
    secret: "chave_super_secreta",
    expiresIn: "1h"
} 


const userSchema = yup.object().shape({
    username: yup.string().required(),
    age: yup.number().positive().required(),
    email:yup.string().required().email(),
    password:yup.string().required(),
    createdOn: yup.date().default(() => new Date())    
})


const tokenIsValid = (req,res,next) => {

    const token = req.headers.authorization.split(" ")[1]

    jwt.verify(token, config.secret, (err) => {

        if (err) {
            return res.status(401).json({message:"Invalid token"})
        }
        
        return next()
    })    

}

const validateSignUp = (schema) => async(req, res, next) => {

    const body = req.body
    
    try {
        await schema.validate(body)
        next()

    } catch (e) {
        res.status(400).json({error: e.errors.join(", ")})

    }
    
}

const doesUserAlreadyExists = (req,res,next) => {

    const { username,email } = req.body

    const user = usersDb.find((userDb) => userDb.email === email || userDb.username === username)

    if (!user) {
        next() 
    } else {
        res.status(409).json({error: "An user with this email or username already exist."})
    }
}


app.listen(port)
app.use(express.json())


app.post("/signup", doesUserAlreadyExists,validateSignUp(userSchema), async (req,res) => {

    const { username, age, email,password } = req.body


    const newUser = {
        uuid: uuidv4(),
        username,
        age,
        email,
        createdOn: new Date()
    }

    usersDb.push({...newUser, password: await bcrypt.hash(password, SALT)})

    res.statusCode = 201
    res.send(newUser)
})


app.post("/login", async (req, res) => {
    
    const { username, password } = req.body

    const user = usersDb.find((userDb) => userDb.username === username)

    if (user) {
        const passwordMatches = await bcrypt.compare(password, user.password)

        if (passwordMatches) {
            const token = jwt.sign(
                { username },
                config.secret,
                { expiresIn: config.expiresIn }
            )

            res.send({token})

        } else {
            res.statusCode = 401
            res.send({error:"Password missmatch"})
        }
        
    } else {
        res.statusCode = 404
        res.send({error:"User dont exist"})
    } 

    
})


app.get("/users", tokenIsValid, (req,res) => {

    res.send(usersDb)

})

app.put("/users/:uuid/password", tokenIsValid, async (req,res) => {
    const { uuid } = req.params
    const { password } = req.body
    const token = req.headers.authorization.split(" ")[1]
    const user = usersDb.find((userDb) => userDb.uuid === uuid)


    const isTheOwner = jwt.verify(token, config.secret, ( _err, decoded) => {

        if (decoded.username !== user.username) {
            return false
        }
        return true
    })  
    
    if (!isTheOwner) {
        res.status(403).json({error:"You cant change a password of another user"})
    }

    if (!user) {
        res.statusCode = 404
        res.send({error:"User not found"})
    }

    const newPassword = await bcrypt.hash(password, SALT)
    user.password = newPassword

    const newDb = usersDb.filter((userDb)=> userDb.uuid !== uuid)
    newDb.push(user)

    usersDb = newDb

    res.statusCode = 204
    res.send('')
})