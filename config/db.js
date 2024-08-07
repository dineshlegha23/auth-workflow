const mongoose = require("mongoose");

const connectDB = async (uri) => {
  try {
    await mongoose.connect(uri);
  } catch (err) {
    console.log(err);
  }
};

module.exports = connectDB;
