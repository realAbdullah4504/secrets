//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require('body-parser');
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");
//const md5=require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;




const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

//for the secret encryption

//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedfields: ["password"] });

const User = new mongoose.model("User", userSchema);



app.get("/", function (req, res) {
    res.render("home");
});


app.get("/login", function (req, res) {
    res.render("login");
});
app.post("/login", function (req, res) {
    User.findOne({ email: req.body.username })
        .then((foundItem) => {
            if (foundItem) {
                

                //compare the encrypted password
                bcrypt.compare(req.body.password, foundItem.password)
                .then((result)=>{
                    if(result){
                        res.render("secrets");
                    }
                })
                .catch((err) => {
                    console.log(err);
                });

                // if (foundItem.password === req.body.password)
                //     res.render("secrets");
                // else
                //     res.render("login");
            }
            else
                res.render("login");
        })
        .catch((err) => {
            console.log(err);
        });


});

app.get("/register", function (req, res) {
    res.render("register");
});

app.post("/register", function (req, res) {

    bcrypt.hash(req.body.password, saltRounds)
        .then((hash) => {

            const user = new User({
                email: req.body.username,
                password: hash
            });

            user.save()
                .then(() => {
                    res.render("secrets");
                })
                .catch((err) => {
                    console.error(err);
                });
        })
        .catch((err) => {
            console.log(err);
        });




});


app.listen(3000, function () {
    console.log("server started");
});
