const express = require("express");
const {
  getAllProducts,
  uploadImage,
  createProduct,
  updateProduct,
  getSingleProduct,
  deleteProduct,
} = require("../controllers/productController");
const { getSingleProductReviews } = require("../controllers/reviewController");
const {
  authenticateUser,
  authorizePermissions,
} = require("../middleware/authentication");
const upload = require("../multer/multer");
const router = express.Router();

router
  .route("/")
  .post(
    [authenticateUser, authorizePermissions("admin", "user")],
    createProduct
  )
  .get(getAllProducts);

router
  .route("/uploadImage")
  .post(
    [
      authenticateUser,
      authorizePermissions("admin", "user"),
      upload.single("image"),
    ],
    uploadImage
  );

router
  .route("/:id")
  .get(getSingleProduct)
  .patch(
    [authenticateUser, authorizePermissions("admin", "user")],
    updateProduct
  )
  .delete(
    [authenticateUser, authorizePermissions("admin", "user")],
    deleteProduct
  );

router.route("/:id/reviews").get(getSingleProductReviews);

module.exports = router;
