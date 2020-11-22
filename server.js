const express = require ('express');
const {pool} = require ('./dbConfig ');
const bcrypt = require ('bcrypt');
const session = require ('express-session');
const flash = require ('express-flash');
const passport = require ('passport');
const {urlencoded} = require ('express');
require ('dotenv').config ();
const app = express ();
const path = require ('path');

//passport; and passport-local; dependencies are to store logedin users session data into our browser cookie so they can use our app as authenticated user

const initializePassport = require ('./passportConfig');
const initialize = require ('./passportConfig');

app.use (express.static ('./views'));
if (process.env.NODE_END === 'production') {
  app.use (express.static (path.join (__dirname, 'view')));
}

initializePassport (passport);

app.set ('view engine', 'ejs');
app.use (express.urlencoded ({extended: false}));

app.use (
  session ({
    secret: 'secret', // incrypt all the information in the session
    resave: false, // should we resave our session variables if nothing is changed? wich is we dont want to do that
    saveUninitialized: false, // do we want to save our session details when there is no values placed in the session? which is we dont want to do that
  })
);

app.use (passport.initialize ());
app.use (passport.session ());

app.use (flash ()); // to display our flash messages

app.get ('/', (req, res) => {
  res.render ('index');
});

app.get ('/users/register', checkAuthenticated, (req, res) => {
  res.render ('register');
});

app.get ('/users/login', checkAuthenticated, (req, res) => {
  res.render ('login');
});

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//   Tjis endpoint will return  an array of objects as json ... each object will be a class(WMclass1)
// it will send an images URLs and the name of the classsess
app.get ('/cyf-classes', function (req, res) {
  pool.query (`select name from batch  `, (err, resuls) => {
    if (err) {
      throw err;
    }
    console.log ('////////////////////////////');
    console.log (resuls.rows);
    console.log ('////////////////////////////');

    if (resuls.rows.length > 0) {
      res.json (resuls.rows);
      //console.log(resuls);
      //  console.log ('Email is already registered');
      // errors.push ({message: 'Email is already registered'});
      // res.render ('register', {errors});
    }
  });
});

///////////////////////////////////////////////////////////////////////////////////////////  Done      ////////////////////////
app.post ('/users/register', async (req, res) => {
  let {name, email, password, password2} = req.body;
  console.log ({
    name,
    email,
    password,
    password2,
  });
  let errors = [];
  if (!name || !email || !password || !password2) {
    errors.push ({message: 'Please fill all of the fields'});
  }

  if (password.length < 6) {
    errors.push ({message: 'Password at least should be 6 characters'});
  }

  if (password != password2) {
    errors.push ({message: 'Passwords do not match'});
  }

  if (errors.length > 0) {
    res.render ('register', {errors});
  } else {
    //form validation has passed
    let hashedPassword = await bcrypt.hash (password, 10);
    console.log (hashedPassword);

    pool.query (
      `select *from users where email = $1`,
      [email],
      (err, resuls) => {
        if (err) {
          throw err;
        }
        //  console.log (resuls.rows);

        if (resuls.rows.length > 0) {
          //  console.log ('Email is already registered');
          errors.push ({message: 'Email is already registered'});
          res.render ('register', {errors});
        } else {
          pool.query (
            `insert into users(id,name,email,password)
            values($1,$2,$3,$4)
         returning id,password `,
            [2, name, email, hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log ('------------ ');
              console.log (results.rows);
              console.log ('------------ ');

              req.flash ('success_msg', 'you are now registered please log in');
              res.redirect ('/users/login');
            }
          );
        }
      }
    );
  }
  // res.send (pool);
});

// This is the final version
/////////////////////////////////////////////////////////////////////////
app.post (
  '/users/login',
  passport.authenticate ('local', {
    successRedirect: '/users/dashboard', // if the login successful
    failureRedirect: '/users/login',
    failureFlash: true, // if we cant authinticate express to render one of the passed failure messages (password not correct or email not registered)
  })
);
///////////////////////////////////////////////////////////////////////////

app.get ('/users/dashboard', checkNotAuthenticated, (req, res) => {
  res.render ('dashBoard', {user: req.user.name});
});

app.get ('/users/logout', (req, res) => {
  req.logOut ();
  req.flash ('success_msg', 'you have logged out');
  res.redirect ('/users/login');
});

function checkAuthenticated (req, res, next) {
  if (req.isAuthenticated ()) {
    return res.redirect ('/users/dashboard');
  }
  next ();
}

function checkNotAuthenticated (req, res, next) {
  if (req.isAuthenticated ()) {
    return next ();
  }
  res.redirect ('/users/login');
}

const PORT = process.env.PORT || 3000;
app.listen (PORT, _ => {
  console.log ('hello world');
});
