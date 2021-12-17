const router = require("express").Router();

const isLoggedIn = require('../middleware/isLoggedIn');

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");

  let userIsLoggedIn = false;
  if (req.session.user) {
    userIsLoggedIn = true;
  }
  res.render('index', { userIsLoggedIn: userIsLoggedIn})
});

module.exports = router;
