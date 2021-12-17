const router = require("espress").Router();
const User = require("./../models/User.model");
const bcrypt = require('bcryptjs');
//const zxcvbn = require('zxcvbn');
const isLoggedIn = require('../middleware/isLoggedIn');
//const res = require("express/lib/response");

const SALT_ROUNDS = 10;

// GET signup
router.get('/signup', (req, res) => {
    res.render('auth/signup-form');
})

// POST signup
router.post('/signup', (req, res) => {
    const { username, password } = req.body;

    const usernameMissing = !username || username === "";
    const passwordMissing = !password || password === "";

    if (usernameMissing || passwordMissing) {
        res.render('auth/signup-form', {
            errorMessage: 'Please define an username and password'
        })
        return;
    }
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;

    if(!regex.test(password)) {
        res.status(400).render('auth/signup-form', {errorMessage: 'Password not secure, try another one.'});
        return;
    }

    User.findOne({ username: username})
        .then((theUser) => {
            if (theUser) {
                throw new Error('You have to choose another username!')
            }
            return bcrypt.genSalt(SALT_ROUNDS);
        })
        .then((salt) => {
            return bcrypt.hash(password, salt);
        })
        .then(hashedPassword => {
            return User.create({ username: username, password: hashedPassword });
        })
        .then((createdUser) => {
            res.redirect('/');
        })
        .cath((err) => {
            res.render('auth/signup-form', {errorMessage: err.message || 'Erro while trying to sign up'})
        })
});

// GET login
router.get('/login', (req, res) => {
    res.render('auth/login-form');
})

//POST login
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    const usernameMissing = !username || username === '';
    const passwordMissing = !password || password === '';

    if (usernameMissing && passwordMissing) {
        res.render('auth/login-form', {
            errorMessage: 'Please introduce username and password.',
        })
        return;
    }
    let user;
    User.findOne({ username: username })
        .then((existsUser) => {
            user = existsUser;
            if (!existsUser) {
                throw new Error('Wrong credentials!');
            }
            return bcrypt.compare(password, existsUser.password);
        })
        .then ((isCorrectPassword) => {
            if (!isCorrectPassword) {
                throw new Error('Wrong credentials!');
            } else if (isCorrectPassword) {
                req.session.user = user;
                res.redirect('/');
            }
        })
        .catch((err) => {
            res.render('auth/signup-form', { errorMessage: err.message || 'Please introduce username and password.'})
        });
})

// GET logout
router.get('/logout', isLoggedIn, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.render('error');
        }
        res.redirect('/');
    })
})

router.get('/private', isLoggedIn, (req, res) => {
    res.render('private');
})

module.exports = router;