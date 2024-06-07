const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

server.use(middlewares);
server.use(bodyParser.json());


const SECRET_KEY = '12324880kskldkjhfkll7889';
const expiresIn = '1h';

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => (decode !== undefined ? decode : err));
}

server.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = router.db.get('users').find({ email, password }).value();
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = createToken({ email, id: user.id });
  return res.status(200).json({ token, user });
});

server.post("/auth/signup", (req, res) => {
  const { email, password, name, username, telephone, location } = req.body;
  const user = router.db.get("users").find({ email }).value();
  if (user) {
    return res.status(409).json({ message: "Email already exists" });
  }
  const newUser = {
    id: Date.now(),
    email,
    password,
    name,
    username,
    telephone,
    location,
    isAdmin: false,
  };
  router.db.get("users").push(newUser).write();
  const token = createToken({
    email,
    id: newUser.id,
    isAdmin: newUser.isAdmin,
  });
  return res.status(200).json({ token, user: newUser });
});

server.use('/api', (req, res, next) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Error in authorization format' });
  }
  try {
    const verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);
    if (verifyTokenResult instanceof Error) {
      return res.status(401).json({ message: 'Access token not provided' });
    }
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Error access_token is revoked' });
  }
});

server.use(router);
server.listen(8000, () => {
  console.log('JSON Server is running on port 3000');
});
