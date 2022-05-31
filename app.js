require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");

mongoose.connect("mongodb://localhost:27017/userData")
const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));
const userSchema = new mongoose.Schema({
  email : String,
  password : String
})
// Encrypting the password field of our schema, to keep the user's password safe
// Note: When we save the new document to our collections, password field will automatically get ecnrypted
// And while searching for particular document in database using Find function encrypted field will automatically get decrypted
// const secret = "Thisourlittlesecret";
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });

const User = new mongoose.model("User", userSchema);
app.get("/", (req, res)=>{
  res.render("home");
})

app.route("/login")
.get((req, res)=>{
  res.render("login");
})
.post((req, res)=>{
  const username = req.body.username;
  const password = req.body.password;
  // Password will be decrypted here
  User.findOne({email:username}, function(err, foundUser){
    if(err){
      console.log(err);
    }
    else{
      if(foundUser){
        // we are checking the hashed password in our database against the hashed password which user entered to login
        // if matches, we let the user go ahead
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if(result){
            res.render("secrets");
          }
        });
      }
    }
  });
});

app.route("/register")
.get((req, res)=>{
  res.render("register");
})
.post((req, res)=>{
  // This will generate hash of given password with saltRounds and will return hash generated
  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash
    })
    newUser.save(function(err){
      if(err){
        console.log(err);
      }
      else{
        res.render("secrets");
      }
    })
  });
});
app.listen(3000, ()=>{
  console.log("Server started on this port.");
})
