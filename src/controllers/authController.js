// Importamos Prisma Client
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Importamos bcrypt para el hash de contraseñas
const bcrypt = require('bcrypt');

// Para generar token aleatorio
const crypto = require('crypto');

// Para enviar correos
const { enviarTokenPorCorreo } = require('../utils/emailSender');

// -----------------------------
// REGISTRO DE USUARIO
// -----------------------------
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.send('El usuario ya existe');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword
      }
    });

    res.status(200).json({ message: 'Usuario creado' });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al registrar usuario');
  }
};

// -----------------------------
// INICIO DE SESIÓN
// -----------------------------
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(400).send('Usuario no encontrado');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).send('Contraseña incorrecta');
    }

    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userEmail = user.email;

    res.send('dashboard'); // Puedes devolver un indicador o redirigir
  } catch (error) {
    console.error(error);
    res.status(500).send('Error en el servidor');
  }
};

// -----------------------------
// CIERRE DE SESIÓN
// -----------------------------
exports.logout = (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error al cerrar sesión');
    }
    res.clearCookie('connect.sid');
    res.redirect('/login.html');
  });
};

// -----------------------------
// RECUPERAR USUARIO POR CORREO
// -----------------------------
exports.recuperarUsuario = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).send('No se encontró un usuario con ese correo');
    }

    res.send(`Tu nombre de usuario es: ${user.name || user.email}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al recuperar el usuario');
  }
};

// -----------------------------
// ENVÍO DE TOKEN POR CORREO + REDIRECCIÓN
// -----------------------------
exports.enviarTokenRecuperacion = async (req, res) => {
  const { email } = req.body;

  try {
    const usuario = await prisma.user.findUnique({ where: { email } });

    if (!usuario) {
      return res.status(404).send('Correo no encontrado.');
    }

    const token = crypto.randomBytes(20).toString('hex');

    await prisma.user.update({
      where: { email },
      data: {
        resetToken: token,
        resetTokenExpiry: new Date(Date.now() + 15 * 60 * 1000),
      },
    });

    await enviarTokenPorCorreo(email, token);

    // 🔁 Redirigir al formulario de recuperación
    res.redirect('/resetear-contrasena.html');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al generar token');
  }
};

// -----------------------------
// CAMBIO DE CONTRASEÑA USANDO TOKEN
// -----------------------------
exports.cambiarContrasena = async (req, res) => {
  const { token, nuevaContrasena } = req.body;

  try {
    const usuario = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiry: {
          gte: new Date(),
        },
      },
    });

    if (!usuario) {
      return res.status(400).send('Token inválido o expirado');
    }

    const hashedPassword = await bcrypt.hash(nuevaContrasena, 10);

    await prisma.user.update({
      where: { id: usuario.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    // ✅ Redirigir a página de confirmación
    res.redirect('/confirmacion-exitosa.html');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al cambiar la contraseña');
  }
};
