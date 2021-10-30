require('dotenv').config()
const express = require("express")
const path = require("path")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')


mongoose.connect('mongodb://127.0.0.1:27017/login-app-db',{
    useNewUrlParser: true,
    useUnifiedTopology : true,
})

const app = express()
app.use('/',express.static(path.join(__dirname,'static')))
app.use(bodyParser.json())


//Routes
app.listen(9999,() => {
    console.log("Server is up at 9999")
})

app.post('/api/change-password', async (req, res) => {
    const { token, newpassword: plainTextPassword } = req.body

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password' })
    }

    if (plainTextPassword.length < 5) {
        return res.json({
            status: 'error',
            error: 'Password too small. Should be atleast 6 characters'
        })
    }

    try {
        const user = jwt.verify(token, `${process.env.JWT_SECRET}`)

        const _id = user.id

        const password = await bcrypt.hash(plainTextPassword, 10)

        await User.updateOne(
            { _id },
            {
                $set: { password }
            }
        )
        res.json({ status: 'ok' })
    } catch (error) {
        console.log(error)
        res.json({ status: 'error', error: ';))' })
    }
})

app.post('/api/login', async (req, res) => {

    const {username , password} = req.body

    //lean will return a simple json document
    const user = await User.findOne({username}).lean()

    if (!user){
        return res.json({status: 'error' , error : 'User not present'})
    }

    if (await bcrypt.compare(password, user.password)){
    //    comparing hash-password of user with plain-password that user sends on login

        const token = jwt.sign({
            id: user._id,
            username: user.username,
        },`${process.env.JWT_SECRET}`)

        return res.json({status: 'ok' , data: token})
    }

    res.json({status: 'error' , error: 'Invalid username/password'})
})

app.post('/api/registerUser',async (req,res) => {

    //Hashing the password needs to be done, so that password are not stored in plain text and is encrypted
    //Make function to convert the password in #hash - bcrypt lib
    const {username , password : plainTextPassword} = req.body

    if (!username || typeof username !== 'string'){
        return res.json({status: "error", error: "Invalid username"})
    }

    if (!plainTextPassword || typeof plainTextPassword !== 'string'){
        return res.json({status: "error", error: "Invalid password"})
    }

    if (plainTextPassword.length < 5){
        return res.json({status: "error", error: "Password must be at least 5 characters"})
    }
    const password = await bcrypt.hash(plainTextPassword,10)

    try{
       const response =  await User.create({
            username,
            password
        })
        console.log('User created' , response)
    }catch (error){
        if (error.code === 11000){
            return res.json({status: 'error' , error: "Username already in use"})
        }
        throw error
    }

    res.json({status: 'ok'})
})