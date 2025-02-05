// Importaciones necesarias
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());

// Conexión a MongoDB
mongoose.connect('mongodb://localhost:27017/ecommerce', { useNewUrlParser: true, useUnifiedTopology: true });

// Definición del modelo User
const userSchema = new mongoose.Schema({
  first_name: String,
  last_name: String,
  email: { type: String, unique: true },
  age: Number,
  password: String,
  cart: { type: mongoose.Schema.Types.ObjectId, ref: 'Cart' },
  role: { type: String, default: 'user' }
});

const User = mongoose.model('User', userSchema);

// Encriptar contraseña
const hashPassword = (password) => bcrypt.hashSync(password, 10);

// Configuración de Passport para estrategia Local
passport.use(
  new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user) return done(null, false, { message: 'Usuario no encontrado' });
      const isMatch = bcrypt.compareSync(password, user.password);
      if (!isMatch) return done(null, false, { message: 'Contraseña incorrecta' });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// Configuración de Passport para estrategia JWT
passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromExtractors([(req) => req.cookies.jwt]),
      secretOrKey: process.env.JWT_SECRET
    },
    async (jwtPayload, done) => {
      try {
        const user = await User.findById(jwtPayload.id);
        if (!user) return done(null, false);
        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

// Registro de usuario
app.post('/api/users/register', async (req, res) => {
  try {
    const { first_name, last_name, email, age, password, cart, role } = req.body;
    const hashedPassword = hashPassword(password);
    const newUser = new User({ first_name, last_name, email, age, password: hashedPassword, cart, role });
    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login de usuario
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.cookie('jwt', token, { httpOnly: true }).json({ message: 'Login exitoso', token });
});

// Ruta protegida con autenticación JWT
app.get('/api/sessions/current', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.json(req.user);
});

// Iniciar servidor
app.listen(3000, () => console.log('Servidor corriendo en puerto 3000'));