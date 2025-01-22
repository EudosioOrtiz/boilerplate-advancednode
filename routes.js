const passport = require('passport');
const bcrypt = require('bcrypt');

module.exports = function (app, myDataBase) {
  app.route('/').get((req, res) => {
    res.render('index', {
      title: 'Connected to Database',
      message: 'Please log in',
      showLogin: true,
      showRegistration: true,
      showSocialAuth: true
    });
  });

  app.route('/login').post(passport.authenticate('local', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/profile');
  });

  app.route('/profile').get(ensureAuthenticated, (req,res) => {
    res.render('profile', { username: req.user.username });
  });

  app.route('/logout').get((req, res) => {
    req.logout();
    res.redirect('/');
  });

  app.route('/register').post((req, res, next) => {
    const hash = bcrypt.hashSync(req.body.password, 12);
    myDataBase.findOne({ username: req.body.username }, (err, user) => {
      if (err) {
        next(err);
      } else if (user) {
        res.redirect('/');
      } else {
        myDataBase.insertOne({
          username: req.body.username,
          password: hash
        },
          (err, doc) => {
            if (err) {
              res.redirect('/');
            } else {
              // The inserted document is held within
              // the ops property of the doc
              next(null, doc.ops[0]);
            }
          }
        )
      }
    })
  },
    passport.authenticate('local', { failureRedirect: '/' }),
    (req, res, next) => {
      res.redirect('/profile');
    }
  );

  app.route('/auth/github').get(passport.authenticate('github'));
  app.route('/auth/github/callback').get(passport.authenticate('github', { failureRedirect: '/' }), (req, res) => {
    req.session.user_id = req.user.id;
    res.redirect("/chat");
  })

  app.use((req, res, next) => {
    res.status(404)
      .type('text')
      .send('Not Found');
  });
}

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
};

/*The basic path this kind of authentication will follow in your app is:

User clicks a button or link sending them to your route to authenticate using a 
specific strategy (e.g. GitHub).
Your route calls passport.authenticate('github') which redirects them to GitHub.
The page the user lands on, on GitHub, allows them to login if they aren't already. 
It then asks them to approve access to their profile from your app.
The user is then returned to your app at a specific callback url with their 
profile if they are approved.
They are now authenticated, and your app should check if it is a returning profile, 
or save it in your database if it is not.
Strategies with OAuth require you to have at least a Client ID and a 
Client Secret which is a way for the service to verify who the authentication 
request is coming from and if it is valid. These are obtained from the site 
you are trying to implement authentication with, such as GitHub, and are 
unique to your app--THEY ARE NOT TO BE SHARED and should never be uploaded 
to a public repository or written directly in your code. 
A common practice is to put them in your .env file and reference them like so: 
process.env.GITHUB_CLIENT_ID. For this challenge you are going to use the GitHub strategy.

Follow these instructions to obtain your Client ID and Secret from GitHub. 
Set the homepage URL to your homepage (not the project code's URL), 
and set the callback URL to the same homepage URL with /auth/github/callback 
appended to the end. Save the client ID and your client secret in 
your project's .env file as GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.

In your routes.js file, add showSocialAuth: true to the homepage route, 
after showRegistration: true. Now, create 2 routes 
accepting GET requests: /auth/github and /auth/github/callback. 
The first should only call passport to authenticate 'github'. 
The second should call passport to authenticate 'github' with a failure 
redirect to /, and then if that is successful redirect 
to /profile (similar to your last project).

An example of how /auth/github/callback should look is similar to 
how you handled a normal login:

app.route('/login')
  .post(passport.authenticate('local', { failureRedirect: '/' }), (req,res) => {
    res.redirect('/profile');
  });*/
