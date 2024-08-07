const Review = require("../models/Review");
const Product = require("../models/Product");

const { checkPermissions, checkPermmissions } = require("../utils");
const { NotFoundError, BadRequestError } = require("../errors");

const createReview = async (req, res) => {
  const { product: productId } = req.body;
  if (!productId) {
    throw new BadRequestError("Please provide product id");
  }

  const isValidProduct = await Product.findOne({ _id: productId });

  if (!isValidProduct) {
    throw new NotFoundError(`No product with id : ${productId}`);
  }

  const alreadySubmitted = await Review.findOne({
    product: productId,
    user: req.user.userId,
  });

  if (alreadySubmitted) {
    throw new BadRequestError("Already submitted review for this product");
  }

  req.body.user = req.user.userId;
  const review = await Review.create(req.body);
  res.status(201).json({ review });
};

const getAllReviews = async (req, res) => {
  const reviews = await Review.find({})
    .populate({
      path: "user",
      select: "name",
    })
    .populate({ path: "product", select: "name company price" });
  res.status(200).json({ reviews, count: reviews.length });
};

const getSingleReview = async (req, res) => {
  const { id: reviewId } = req.params;
  const review = await Review.findOne({ _id: reviewId });
  if (!review) {
    throw new NotFoundError(`Review not found with id : ${reviewId}`);
  }
  res.status(200).json(review);
};

const updateReview = async (req, res) => {
  const { id: reviewId } = req.params;
  const { title, comment, rating } = req.body;
  const review = await Review.findOne({ _id: reviewId });
  if (!review) {
    throw new NotFoundError(`Review not found with id : ${reviewId}`);
  }
  checkPermmissions(req.user, review.user);
  review.rating = rating;
  review.title = title;
  review.comment = comment;
  await review.save();
  res.status(200).json({ review });
};

const deleteReview = async (req, res) => {
  const { id: reviewId } = req.params;
  const review = await Review.findOne({ _id: reviewId });
  if (!review) {
    throw new NotFoundError(`Review not found with id : ${reviewId}`);
  }
  checkPermmissions(req.user, review.user);
  await Review.deleteOne({ _id: reviewId });
  res.status(200).json("review deleted");
};

const getSingleProductReviews = async (req, res) => {
  const { id: productId } = req.params;
  const reviews = await Review.find({ product: productId });
  res.status(200).json({ reviews, count: reviews.length });
};

module.exports = {
  createReview,
  getAllReviews,
  getSingleReview,
  updateReview,
  deleteReview,
  getSingleProductReviews,
};
