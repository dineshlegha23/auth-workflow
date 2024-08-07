const fs = require("fs");
const { NotFoundError, BadRequestError } = require("../errors");
const Product = require("../models/Product");

const createProduct = async (req, res) => {
  req.body.user = req.user.userId;
  const product = await Product.create(req.body);
  res.status(201).json({ product });
};

const getAllProducts = async (req, res) => {
  const products = await Product.find({});
  res.status(200).json({ total: products.length, products });
};

const getSingleProduct = async (req, res) => {
  const { id: productId } = req.params;
  const product = await Product.findOne({ _id: productId }).populate("reviews");
  if (!product) {
    throw new NotFoundError(`Product not found with ID : ${productId}`);
  }
  res.status(200).json({ product });
};

const updateProduct = async (req, res) => {
  const { id: productId } = req.params;
  const product = await Product.findOneAndUpdate({ _id: productId }, req.body, {
    new: true,
    runValidators: true,
  });
  if (!product) {
    throw new NotFoundError(`Product not found with ID : ${productId}`);
  }
  res.status(200).json({ product });
};

const deleteProduct = async (req, res) => {
  const { id: productId } = req.params;
  const product = await Product.findOne({ _id: productId });

  if (!product) {
    throw new NotFoundError(`Product not found with ID : ${productId}`);
  }
  await product.deleteOne();
  res.status(200).json({});
};

const uploadImage = async (req, res) => {
  if (!req.file) {
    throw new BadRequestError("No File Uploaded");
  }
  const productImage = req.file;
  if (!productImage.mimetype.startsWith("image")) {
    throw new BadRequestError("Please Upload Image");
  }
  const maxSize = 6024 * 1024;
  if (productImage.size > maxSize) {
    throw new BadRequestError("Please upload image smaller than 6MB");
  }
  //   fs.unlinkSync(`${__dirname}/../public/uploads/${productImage.filename}`);
  res.send("Upload image working");
};

module.exports = {
  createProduct,
  getAllProducts,
  getSingleProduct,
  updateProduct,
  deleteProduct,
  uploadImage,
};
