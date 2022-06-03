require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

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

mongoose.connect("mongodb://localhost:27017/userData")

const userSchema = new mongoose.Schema({
  email : String,
  password : String
})
userSchema.plugin(passportLocalMongoose);
// Encrypting the password field of our schema, to keep the user's password safe
// Note: When we save the new document to our collections, password field will automatically get ecnrypted
// And while searching for particular document in database using Find function encrypted field will automatically get decrypted
// const secret = "Thisourlittlesecret";
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
app.get("/", (req, res)=>{
  res.render("home");
})

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
  console.log("Server started on this port.");
})
