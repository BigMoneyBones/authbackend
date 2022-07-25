var express = require("express");
var router = express.Router();

// npm i bcryptjs uuidv4
// bcrypt gives us access to password generation and authentication funcionality for logging users in to our application.
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");

const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
dotenv.config();

// implement the user creation route using the bcrypt salt/hash functions to take our new users password and encrypt it before saving it to the database.
const createUser = async (username, passwordHash) => {
  // Note: You do not have to create the users collection in mongodb before saving to it. Mongo will automatically create the users collection upon insert of a new document.
  const collection = await blogsDB().collection("users");

  const user = {
    username: username,
    password: passwordHash,
    uid: uuid(), // uid stands for User ID. This will be a unique string that we can use to identify our user.
  };
  console.log("mongo response " + collection);
  try {
    // Save user functionality
    await collection.insertOne(user);
    return true;
  } catch (error) {
    console.log("something is wrong");
    console.error(error);
    return false;
  }
};

router.post("/register-user", async (req, res, next) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const saltRounds = 5; // In a real application, this number would be somewhere between 5 and 10
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    const userSaveSuccess = await createUser(username, hash);
    // console.log(userSaveSuccess);
    res.json({ success: userSaveSuccess }).status(200);
  } catch (e) {
    res.json({ success: false }).status(500);
  }
});

router.post("/login-user", async (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const collection = await blogsDB().collection("users");
  try {
    const user = await collection.findOne({
      username: username,
    });
    if (!user) {
      res.json({ success: false }).status(204);
    }
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      const jwtSecretKey = process.env.JWT_SECRET_KEY;
      const data = {
        time: new Date(),
        userId: user.uid, // Note: Double check this line of code to be sure that user.uid is coming from your fetched mongo user
      };

      const token = jwt.sign(data, jwtSecretKey);
      res.json({ success: true, token }).status(200);
      return;
    }
    res.json({ success: false });
  } catch (error) {
    res.json({ message: "Error Logging In.", success: false }).status(500);
  }
});

router.get("/validate-token", async (req, res, next) => {
  const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
  const jwtSecretKey = process.env.JWT_SECRET_KEY;

  try {
    const token = req.header(tokenHeaderKey);
    const verified = jwt.verify(token, jwtSecretKey);

    if (verified) {
      return res.json({ success: true });
    } else {
      // Access Denied
      throw Error("Access Denied");
    }
  } catch (error) {
    // Access Denied
    return res.status(401).json({ success: error, message: String(error) });
  }
});

module.exports = router;
