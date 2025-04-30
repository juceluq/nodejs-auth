import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { UserRepository } from './user-repository.js';
import { PORT, SECRET_JWT_KEY } from './config.js';

const app = express();

app.set('view engine', 'ejs');
app.disable('x-powered-by');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use((req, res, next) => {
  const token = req.cookies.access_token;
  req.session = { user: null };

  if (token) {
    try {
      const data = jwt.verify(token, SECRET_JWT_KEY);
      req.session.user = data;
    } catch (err) {
    }
  }

  next();
});

app.get('/', (req, res) => {
  const { user } = req.session;
  const error = req.query.error;
  const success = req.query.success;

  res.render('index', {
    username: user?.username,
    error,
    success
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await UserRepository.login({ username, password });

    const accessToken = jwt.sign({ id: user._id, username: user.username }, SECRET_JWT_KEY, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user._id, username: user.username }, SECRET_JWT_KEY, { expiresIn: '7d' });

    res
      .cookie('access_token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60,
      })
      .cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 24 * 7,
      })
      .redirect('/');
  } catch (error) {
    res.redirect('/?error=' + encodeURIComponent(error.message));
  }
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    await UserRepository.create({ username, password });
    res.redirect('/?success=' + encodeURIComponent('Usuario registrado correctamente.'));
  } catch (error) {
    res.redirect('/?error=' + encodeURIComponent(error.message));
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('access_token')
    .clearCookie('refresh_token')
    .redirect('/?success=' + encodeURIComponent('Sesión cerrada correctamente.'));
});

app.post('/refresh-token', (req, res) => {
  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {
    return res.status(401).send('Refresh token missing');
  }

  try {
    const data = jwt.verify(refreshToken, SECRET_JWT_KEY);
    const newAccessToken = jwt.sign({ id: data.id, username: data.username }, SECRET_JWT_KEY, { expiresIn: '1h' });

    res
      .cookie('access_token', newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60,
      })
      .json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).send('Invalid refresh token');
  }
});

app.get('/protected', (req, res) => {
  const { user } = req.session;
  if (!user) {
    return res.status(403).render('protected', { authorized: false });
  }
  res.render('protected', { authorized: true, username: user.username });
});

app.use((req, res, next) => {
  const errorMessage = 'La URL solicitada no es válida.';
  res.redirect('/?error=' + encodeURIComponent(errorMessage));
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
