const express = require('express');
const app = express();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const PORT = process.env.PORT || 3000;

const { User } = require('./models');

const bcrypt = require('bcrypt');
const saltRounds = 5;

app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: 'tacocat',
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  },
  resave: true,
  saveUninitialized: true,
}));

app.use(express.static(__dirname + '/public'))

app.post('/api/register', (req, res) => {
  const { firstName, lastName, email, password, username } = req.body;

  if (!email || !password || !username) {
    return res.json({ err: 'email, username and password are required' });
  }

  console.log(req.body)

  let hashedPassword = bcrypt.hashSync(password, saltRounds);

  User.create({
    firstName, lastName, email, password: hashedPassword, username
  }).then(new_user => {
    req.session.user = new_user;
    res.json(new_user);
  })
})

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  User.findOne({
    where: {
      email
    }
  }).then(user => {
    if (!user) {
      return res.json({ err: 'no user found' });
    }

    let comparedPassword = bcrypt.compareSync(password, user.password);
    if (comparedPassword) {
      req.session.user = user;
      res.json({ success: true })
    } else {
      res.json({ success: false, err: 'bad password' })
    }
  })
})

app.get('/api/user', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, err: 'please login' })
  }

  User.findByPk(req.session.user.id,
    {
      fields: ['id', 'firstName', 'lastName', 'email', 'username', 'bio', 'hobbies']
    }).then(user => {
      req.session.user = user;
      res.json({ success: true, user: user })
    })
})

app.put('/api/user', (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, err: 'please login' })
  }

  const { firstName, lastName, password, bio, hobbies } = req.body;

  const updateFields = {};

  if (firstName) {
    updateFields.firstName = firstName;
  }

  if (lastName) {
    updateFields.lastName = lastName;
  }

  if (password) {
    updateFields.password = bcrypt.hashSync(password, saltRounds);
  }

  if (bio) {
    updateFields.bio = bio;
  }

  if (hobbies) {
    updateFields.hobbies = hobbies;
  }

  if (Object.keys(updateFields).length === 0) {
    return res.json({ success: false, err: 'no fields to update' });
  }

  User.update(updateFields, {
    where: {
      id: req.session.user.id
    }
  }).then((result) => {
    console.log(result)
    res.json({ success: true })
  })
})

app.listen(PORT, () => {
  console.log('app started in port ' + PORT);
})