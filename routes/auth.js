var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");

const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
dotenv.config();

const createUser = async (username, passwordHash) => {
  const collection = await blogsDB().collection("users");

  const user = {
    username: username,
    password: passwordHash,
    uid: uuid(), // uid stands for User ID. This will be a unique string that we can use to identify our user.
  };

  try {
    // Save user functionality
    await collection.insertOne(user);
    return true;
  } catch (e) {
    console.error(e);
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
    res.json({ success: userSaveSuccess }).status(200);
  } catch (e) {
    res.json({ success: false }).status(500);
  }
});

router.post("/login-user", async (req, res, next) => {
  try {
    const collection = await blogsDB().collection("users");
    const user = await collection.findOne({
      username: req.body.username,
    });

    const match = await bcrypt.compare(req.body.password, user.password);

    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const data = {
      time: new Date(),
      userId: user.uid, // Note: Double check this line of code to be sure that user.uid is coming from your fetched mongo user
    };
    const token = jwt.sign(data, jwtSecretKey);

    res.json({ success: true, token }).status(200);
  } catch (e) {
    res.json({ success: false }).status(500);
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
    return res.status(401).json({ success: true, message: String(error) });
  }
});

module.exports = router;
