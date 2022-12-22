import UserModel from '../models/User.js'
// import ProductModel from '../models/Product.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import transporter from '../config/emailConfig.js'
import nodemailer from 'nodemailer'

class UserController {
  static userRegistration = async (req, res) => {
    const { name, email, password, password_confirmation, IMEI, tc } = req.body;
    const user = await UserModel.findOne({ email: email });
    if (user) {
      res.send({ status: "failed", message: "Бүртгэлтэй Имайл байна?" });
    } else {
      if (name && email && password && password_confirmation && IMEI && tc) {
        if (password === password_confirmation) {
          try {
            const salt = await bcrypt.genSalt(10);
            const hashPassword = await bcrypt.hash(password, salt);
            const doc = new UserModel({
              name: name,
              email: email,
              password: hashPassword,
              IMEI: IMEI,
              tc: tc,
            });
            await doc.save();
            const saved_user = await UserModel.findOne({ email: email });
            // Generate JWT Token
            const token = jwt.sign(
              { userID: saved_user._id },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "5d" }
            );
            res.status(201).send({
              status: "success",
              message: "амжилттай бүртгэлээ",
              token: token,
              IMEI: IMEI,
            });
          } catch (error) {
            console.log(error);
            res.send({ status: "failed", message: "Бүртгэх боломжгүй" });
          }
        } else {
          res.send({
            status: "failed",
            message: "Баталгаажуулах нууц үг тохирохгүй байна",
          });
        }
      } else {
        res.send({ status: "failed", message: "Мэдээлэл дутуу байна?" });
      }
    }
  };

  static userLogin = async (req, res) => {
    try {
      const { email, password } = req.body
      if (email && password) {
        const user = await UserModel.findOne({ email: email })
        if (user != null) {
          const isMatch = await bcrypt.compare(password, user.password)
          if ((user.email === email) && isMatch) {
            // Generate JWT Token
            const token = jwt.sign({ userID: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' })
            res.send({ "status": "success", "message": "Login Success", "token": token })
          } else {
            res.send({ "status": "failed", "message": "Имайл эсвэл нууц үг буруу байна?" })
          }
        } else {
          res.send({ "status": "failed", "message": "Бүртгэлгүй хэрэглэгч байна?" })
        }
      } else {
        res.send({ "status": "failed", "message": "Мэдээлэл оруулна уу?" })
      }
    } catch (error) {
      console.log(error)
      res.send({ "status": "failed", "message": "Нэвтрэх боломжгүй" })
    }
  }

  static changeUserPassword = async (req, res) => {
    const { password, password_confirmation } = req.body;
    if (password && password_confirmation) {
      if (password !== password_confirmation) {
        res.send({
          status: "failed",
          message: "Баталгаажуулах нууц үг тохирохгүй байна",
        });
      } else {
        const salt = await bcrypt.genSalt(10);
        const newHashPassword = await bcrypt.hash(password, salt);
        await UserModel.findByIdAndUpdate(req.user._id, {
          $set: { password: newHashPassword },
        });
        res.send({ status: "success", message: "Нууц үг амжилттай солигдлоо" });
      }
    } else {
      res.send({ status: "failed", message: "Мэдээлэл оруулна уу?" });
    }
  };

  static loggedUser = async (req, res) => {
    res.send({ user: req.user });
  };

  static sendUserPasswordResetEmail = async (req, res) => {
    const { email } = req.body
    if (email) {
      const user = await UserModel.findOne({ email: email })
      if (user) {
        const secret = user._id + process.env.JWT_SECRET_KEY
        const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '15m' })
        const resetCode = `http://192.168.0.112:3000/api/user/reset/${user._id}/${token}`
        console.log(resetCode)
         // Send Email
          //  let info = await transporter.sendMail({
          //    from: process.env.EMAIL_FROM,
          //    to: user.email,
          //    subject: "product - Password Reset resetCode",
          //    html: `<a href=${resetCode}>Click Here</a> to Reset Your Password`
          //  })

        res.send({ "status": "success", "message": "Password Reset Email Sent... Please Check Your Email" })
      } else {
        res.send({ "status": "failed", "message": "Email doesn't exists" })
      }
    } else {
      res.send({ "status": "failed", "message": "Email Field is Required" })
    }
  }
//   static sendUserPasswordResetEmail = async (email, subject, text) => {
//     try {
//         const transporter = nodemailer.createTransport({
//             host: process.env.HOST,
//             service: process.env.SERVICE,
//             port: 3000,
//             secure: true,
//             auth: {
//                 user: process.env.USER,
//                 pass: process.env.PASS,
//             },
//         });

//         await transporter.sendMail({
//             from: process.env.USER,
//             to: email,
//             subject: subject,
//             text: text,
//         });

//         console.log("email sent sucessfully");
//     } catch (error) {
//         console.log(error, "email not sent");
//     }
// };

  static userPasswordReset = async (req, res) => {
    const { password, password_confirmation } = req.body;
    const { id, token } = req.params;
    const user = await UserModel.findById(id);
    const new_secret = user._id + process.env.JWT_SECRET_KEY;
    try {
      jwt.verify(token, new_secret);
      if (password && password_confirmation) {
        if (password !== password_confirmation) {
          res.send({
            status: "failed",
            message: "Баталгаажуулах нууц үг тохирохгүй байна",
          });
        } else {
          const salt = await bcrypt.genSalt(10);
          const newHashPassword = await bcrypt.hash(password, salt);
          await UserModel.findByIdAndUpdate(user._id, {
            $set: { password: newHashPassword },
          });
          res.send({ status: "success", message: "Нууц амжилттай сэргээлээ" });
        }
      } else {
        res.send({ status: "failed", message: "Мэдээлэл оруулна уу?" });
      }
    } catch (error) {
      console.log(error);
      res.send({ status: "failed", message: "Invalid Token" });
    }
  };

  // static productRegistration = async (req, res) => {
  //   const { name, code, account, qauntity, owner, price, register, Date} =
  //     req.body;
  //   const product = await ProductModel.findOne({
  //     name: name,
  //     code: code,
  //     account: account,
  //     qauntity: qauntity,
  //     owner: owner,
  //     price: price,
  //     register: register,
  //     Date: Date,
  //   });
  //   if (product) {
  //     res.send({ status: "failed", message: "Бүртгэсэн бараа байна?" });
  //   } else {
  //     if (
  //       name &&
  //       code &&
  //       account &&
  //       qauntity &&
  //       owner &&
  //       price &&
  //       register &&
  //       Date
  //     ) {
  //       try {
  //         const doc = new ProductModel({
  //           name: name,
  //           code: code,
  //           account: account,
  //           qauntity: qauntity,
  //           owner: owner,
  //           price: price,
  //           register: register,
  //           Date: Date,
  //         });
  //         await doc.save();
  //         const saved_product = await ProductModel.findOne({
  //           name: name,
  //           code: code,
  //           account: account,
  //           qauntity: qauntity,
  //           owner: owner,
  //           price: price,
  //           register: register,
  //           Date: Date,
  //         });
  //            const token = jwt.sign(
  //              { userID: saved_product._id },
  //              process.env.JWT_SECRET_KEY,
  //              { expiresIn: "5d" }
  //            );
  //         res.status(201).send({
  //           status: "success",
  //           message: "амжилттай бүртгэлээ",
  //            token: token,
  //         });
  //       } catch (error) {
  //         console.log(error);
  //         res.send({ status: "failed", message: "Бүртгэх боломжгүй" });
  //       }
  //     }
  //   }
  // };
}

export default UserController;
