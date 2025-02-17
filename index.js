const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { expressjwt: expressJwt } = require('express-jwt')
const User = require('./user')

mongoose.connect('mongodb+srv://alexismouwid:yosoyotaku23.@intro-mondodb.19ttj.mongodb.net/?retryWrites=true&w=majority&appName=Intro-Mondodb')
      .then(() => console.log('Conectado a MongoDB'))
      .catch(err => {
        console.error('Error al conectar a MongoDB:', err.message);
        process.exit(1); // Detiene la app si falla la conexión
      });

const app = express()

app.use(express.json())
console.log(process.env.SECRET)

const validateJwt = expressJwt({ secret: process.env.SECRET , algorithms: ['HS256'] })
const signToken = _id => jwt.sign({ _id }, process.env.SECRET)

app.post('/register', async (req, res) => {
  const { body } = req
  try {
        const isUser = await User.findOne({ email: body.email })
        if (isUser) {
            return res.status(403).send('Usuario ya existe')
        }
        const salt = await bcrypt.genSalt()
        const hashed =  await bcrypt.hash(body.password, salt)
        const user = await User.create({ email: body.email, password: hashed, salt })
        const signed = signToken(user._id)
        res.status(201).send(signed)
        console.log(`Usuario creado con éxito. ${body.email}`)
  } catch (err) {
    console.log(err)
    res.status(500).send(err.message)
  }
})

app.post('/login', async (req, res) => {
    const { body } = req
    try {
        const user = await User.findOne({ email: body.email })
        if (!user) {
            return res.status(403).send('Usuario y/o contraseña inválida')
        }

        const isMatch = await bcrypt.compare(body.password, user.password)
        if (!isMatch) {
            return res.status(403).send('Usuario y/o contraseña inválida')
        }

        const signed = signToken(user._id)
        res.status(200).json(signed)
        console.log(`${body.email} ha iniciado sesión`)
     } catch (err) {
        console.error(err)  // Log para depuración
        res.status(500).send('Error en el servidor, inténtalo más tarde')
     }
})

const findAndAssignUser =   async (req, res, next) => {
    try{
        const user  = await User.findById(req.auth._id)
            if(!user){
               return res.status(401).end()
            }
     req.auth = user
     next()
     } catch (e) {
     next(e)
     }

}
const isAuthenticated = express.Router().use(validateJwt, findAndAssignUser)
app.get('/lele', isAuthenticated, (req, res) => {
   res.send(req.auth)
})

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).send('Token no válido o no proporcionado')
  }
  next(err) // Pasa al siguiente middleware si no es un error de autorización
})

app.listen(3000, () => {
  console.log('listening on port 3000')
})

