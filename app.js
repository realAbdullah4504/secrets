//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require('body-parser');
const ejs = require("ejs");
const mongoose = require("mongoose");

// for passport
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const LocalStrategy = require("passport-local")

// FOR GOOGLE OAUTH
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require("mongoose-findorcreate");




const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

//for the session
app.use(session({
    secret: "our little secret .",
    resave: false,
    saveUninitialized: false
}));

//passport initialize
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String
});
//for passport user schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

passport.use(new LocalStrategy(User.authenticate()));

//for serialize in the google oauth we dont use the serialize method for mongoose
//we use what we have provided with the passport.js
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    //should install the package mongoose findorcreate
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/", function (req, res) {
    res.render("home");
});

//for google authenticate
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/logout", function (req, res) {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});

app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err, user) {
        if (err)
            console.error(err);
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("secrets");
            });
        }
    });

});



app.get("/secrets", function (req, res) {
    if (req.isAuthenticated())
        res.render("secrets");
    else
        res.render("login");

});

app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err)
            console.error(err);
        else {
            //this call back only works when it authenticate
            passport.authenticate("local")(req,res,function () {
                res.redirect("secrets");
            });
        }
    });
});



app.listen(3000, function () {
    console.log("server started");
});
