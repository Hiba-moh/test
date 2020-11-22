const LocalStrategy = require ('passport-local').Strategy;
const {pool} = require ('./dbConfig ');
const bcrypt = require ('bcrypt'); // to compare our user password to the hashed password stored into the database
const {authenticate} = require ('passport');

function initialize (passport) {
  const authenticateUser = (email, password, done) => {
    pool.query (
      `select *from users where email = $1`,
      [email],
      (err, results) => {
        if (err) {
          throw err;
        }
        console.log (results.rows);
        if (results.rows.length > 0) {
          const user = results.rows[0]; // if the user been found in the database .. it will be stored in the variable user
          bcrypt.compare (password, user.password, (err, isMatch) => {
            if (err) {
              throw err;
            }
            if (isMatch) {
              return done (null, user); // will return the user and store it in the session cookie object .. coz there is null err
            } else {
              return done (null, false, {message: 'password is not correct'}); // false password
            }
          });
        } else {
          // if there are no useres found in the database
          return done (null, false, {message: 'Email is not registered'});
        }
      }
    );
  };

  passport.use (
    new LocalStrategy (
      {
        usernameField: 'email',
        passwordField: 'password',
      },
      authenticateUser
    )
  );

  passport.serializeUser ((user, done) => done (null, user.id));
  passport.deserializeUser ((id, done) => {
    pool.query (`select *from users where id = $1`, [id], (err, results) => {
      if (err) {
        throw err;
      }
      return done (null, results.rows[0]);
    });
  });
}

module.exports = initialize;
