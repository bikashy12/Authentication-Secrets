require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const Strategy = require('passport-google-oauth20/lib');
const FacebookStrategy = require("passport-Facebook").Strategy;
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");
const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
  secret: "Our little secret",
  resave: false,
  saveUninitialized:false
}))
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userData");

const userSchema = new mongoose.Schema({
  email : String,
  password : String,
  googleId:String,
  facebookId: String,
  secret:[]
})
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// Encrypting the password field of our schema, to keep the user's password safe
// Note: When we save the new document to our collections, password field will automatically get ecnrypted
// And while searching for particular document in database using Find function encrypted field will automatically get decrypted
// const secret = "Thisourlittlesecret";
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// This way we can implement any strategy along with local Strategy
passport.serializeUser((user, done)=>{
  done(null, user.id);
});

passport.deserializeUser((id, done)=>{
  User.findById(id, (err, user)=>{
    done(err, user);
  })
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  function(accessToken, refreshToken, profile, cb) {
    // Google sends back access Token through which we can have access to user data for longer time
    // Profile contains the email, googleId and many more info related to user
    console.log(profile);
    User.findOrCreate({ googleId: profile.id , username: profile.name.givenName}, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id , username : profile.displayName}, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res)=>res.render("home"));
app.route("/login")
.get((req, res)=>{
  res.render("login");
})
.post((req, res)=>{
  const user = new User({
    username:req.body.username,
    password: req.body.password
  })
  req.login(user, (err)=>{
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req, res, ()=> res.redirect("/secrets"));
    }
  })
  // const username = req.body.username;
  // const password = req.body.password;
  // // Password will be decrypted here
  // User.findOne({email:username}, function(err, foundUser){
  //   if(err){
  //     console.log(err);
  //   }
  //   else{
  //     if(foundUser){
  //       // we are checking the hashed password in our database against the hashed password which user entered to login
  //       // if matches, we let the user go ahead
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if(result){
  //           res.render("secrets");
  //         }
  //       });
  //     }
  //   }
  // });
});

app.get("/secrets", (req, res)=>{
  if(req.isAuthenticated()){
    res.render("secrets");
  }else{
    res.redirect("/login");
  }
})

app.get("/logout",(req, res)=>{
  req.logout(function(err){
    if(err){
      console.log(err);
    }
  });
  res.redirect("/");
})

app.get("/auth/google", passport.authenticate('google', { scope: ["profile"] }));
  // After clicking on the google button, we will be directed to this route and this will authenticate with
  // google server and ask for user profile once user have logged in

app.get("/auth/google/secrets",
  // Authenticating the user locally and saving login session, If Authentication fails
  // User will directed to login page, otherwise to the secrets page
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/secrets");
  });

app.get("/auth/facebook", passport.authenticate('facebook'));

app.get("/auth/facebook/secrets",
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/secrets");
  });

app.route("/submit")
.get((req, res)=>{
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
})
.post((req, res)=>{
  User.findById(req.user.id, (err, doc)=>{
    // console.log((req.user)); 
    doc.secret.push(req.body.secret);
    doc.save(function(err){
      if(err){
        res.send(err);
      }
    });
    let allSecret = []; 
    (doc.secret).forEach((found)=>{
      allSecret.push(found); 
    })
    console.log(allSecret);
    res.render("secrets", {allSecret,});
    allSecret = []; 
    // console.log(doc.secret);
  })
});


app.route("/register")
.get((req, res)=>{
  res.render("register");
})
.post((req, res)=>{
  User.register({username:req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req, res, ()=>{res.redirect("/secrets")});
    }
  });
  // // This will generate hash of given password with saltRounds and will return hash generated
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   })
  //   newUser.save(function(err){
  //     if(err){
  //       console.log(err);
  //     }
  //     else{
  //       res.render("secrets");
  //     }
  //   })
  // });
});
app.listen(3000, ()=>{
  console.log("Server started on port 3000");
})
