const { Router } = require('express');
const router = new Router();

const User = require('../models/User.model');

const bcryptjs = require('bcryptjs');

const saltRounds = 10;

const { isLoggedIn, isLoggedOut } = require('../middleware/isLogged.js');

// Signup

// GET route 
router.get('/signup', isLoggedOut, (req, res) => res.render('auth/signup'));

// POST route
router.post('/signup', isLoggedOut, (req, res, next) => {
    
    const { username, password } = req.body;
 
  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
        return User.create({
            username,
            passwordHash: hashedPassword
        });
    })
    .then(userFromDB => {
        console.log('New created user is: ', userFromDB);
        res.redirect('/userProfile');
    })
    .catch(error => next(error));
  });


// Login

// GET route
router.get('/login', isLoggedOut, (req, res) => res.render('auth/login'));

// POST route
router.post('/login', isLoggedOut, (req, res, next) => {
  console.log('SESSION =====> ', req.session);

  const { username, password } = req.body;
 
  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter username and password to login.'
    });
    return;
  }
 
  User.findOne({ username })     
    .then(user => {     
                       
      if (!user) {      
        res.render('auth/login', { errorMessage: 'Username is not registered. Try with other username.' });
        return;
      } 
      
        else if (bcryptjs.compareSync(password, user.passwordHash)) {
      
        req.session.user = user;
        res.redirect('/userProfile');
      } else {
      
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));  
});


// Logout

router.post('/logout', isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});


router.get('/userProfile', isLoggedIn, (req, res) => {
  res.render('users/user-profile', { userInSession: req.session.user });
});

module.exports = router;