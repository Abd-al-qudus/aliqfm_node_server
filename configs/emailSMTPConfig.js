const nodemailer = require('nodemailer');
const mailGenerator = require('mailgen');
const dotenv = require('dotenv');

dotenv.config();

const emailRegistration = async (req, res) => {
    const smtpConfig = {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: false,
        auth: {
            user: process.env.SMTP_EMAIL,
            pass: process.env.SMTP_PASSWORD
        }
    }
  const transporter = nodemailer.createTransport(smtpConfig);
  const mailGen = new mailGenerator({
    theme: "default",
    product: {
      name: "MailGen",
      link: "https://mailgen.js"
    }
  });
  try {
    const OTP = req.app.locals.OTP;
    const email = req.user.email;
    const subject  = req.query.subject;
    console.log(OTP, query)
    if (typeof subject !== "string" || typeof email !== "string") return res.sendStatus(403);
    if (!email || !subject) return res.status(400).json({ 'error': 'missing email or subject' });
    const mail = {
      body: {
      name: email,
      intro: OTP ? ['Welcome to Al-Iqmah!!!', `your OTP is ${OTP}`] : ['Welcome to Al-Iqmah!!!', 'your registration has been completed successfully.'],
      outro: "This email is automatically generated upon user verification."
      }
    }
    const body = await mailGen.generate(mail);
    const message = {
      from: process.env.SMTP_EMAIL,
      to: email,
      subject: subject,
      html: body
    }
    await transporter.sendMail(message);
    return res.status(200).json({ "error": "check your email for confirmation" });
  } catch (error) {
    return res.status(500).json({ error });
  }
}


module.exports = emailRegistration;
