import * as nodemailer from 'nodemailer';
require('dotenv').config();

const user = process.env.GmailUser;
const pass = process.env.GmailPass;



export const transporter = nodemailer.createTransport({
  service: 'gmail', // SAME AS HOST
  auth: {
    user: user,
    pass: pass,
  },
  tls: {
    rejectUnauthorized: false, //TELLING THE NODEMAILER TO ENSURE THAT
    //THE MAIL IS SENT TO THE USER AND SEND RESPONSE IF IT COULD NOT DELIVER PROBABLY DUE TO WRONG EMAIL ADDRESS
  },
});

export const mailsent = async (
  from: string,
  to: string,
  subject: string,
  html: string,
) => {
  try {
    const from = process.env.FromAdminMail;
    //THE ARRANGEMENT BELOW IS IMPORTANT. FROM-TO-SUBJECT-HTML
    const response = await transporter.sendMail({
      from: from,
      to,
      subject,
      html,
    });
    
    return response;
  } catch (err) {
    console.log(err);
  }
};

export const resetPasswordmailHtml = (email: string): string => {
  let response = `
  <table width="95%" border="0" align="self-start" cellpadding="0" cellspacing="0" style="max-width:670px;background:#fff; border-radius:3px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
  <tr>
    <td style="height:40px;">&nbsp;</td>
  </tr>
  <tr>
  
    <td style="padding:0 35px;">
    <img src="/Users/decagon/Desktop/BankAppBackend/src/utils/logo.png" alt="logo">

      <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">Reset password</h1>
      <span style="display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;"></span>
      <p style="color:#455056; font-size:15px;line-height:24px; margin:0; text-align:start;">
        Hi! <br/> We received a request to reset your password. <br/>

Please click on the link below to proceed.
      </p>
      <a href="https://all-well-color-test.netlify.app/create-password/${email}" style="background:#4EE0BC;text-decoration:none !important; font-weight:500; margin-top:35px; color:#fff; font-size:14px;padding:10px 24px;display:inline-block;border-radius:50px; width:10rem;">Reset your password</a>
      <p style="color:#455056; font-size:15px;line-height:24px; margin-top:50px; text-align:start;">
        The All Well team
      </p>
    </td>
  </tr>
  <tr>
    <td style="height:40px;">&nbsp;</td>
  </tr>
</table>
</td>
<tr>
<td style="height:20px;">&nbsp;</td>
</tr>
<tr>
<td style="text-align:center;">
</td>
</tr>
<tr>
<td style="height:80px;">&nbsp;</td>
</tr>
</table>
</td>
</tr>
<tr>
<td style="padding: 10px 10px 5px;" align="center" valign="top" class="brandInfo">
<p class="text" style="color:#bbb;font-family:'Open Sans',Helvetica,Arial,sans-serif;font-size:12px;font-weight:400;font-style:normal;letter-spacing:normal;line-height:20px;text-transform:none;text-align:center;padding:0;margin:0">©&nbsp;All well Inc. | 800 Broadway, Suite 1500 | New York, NY 000123, USA.</p>
</td>
</tr>
<tr>
<td style="padding: 0px 10px 20px;" align="center" valign="top" class="footerLinks">
<p class="text" style="color:#bbb;font-family:'Open Sans',Helvetica,Arial,sans-serif;font-size:12px;font-weight:400;font-style:normal;letter-spacing:normal;line-height:20px;text-transform:none;text-align:center;padding:0;margin:0"> <a href="#" style="color:#bbb;text-decoration:underline" target="_blank">View Web Version </a>&nbsp;|&nbsp; <a href="#" style="color:#bbb;text-decoration:underline" target="_blank">Email Preferences </a>&nbsp;|&nbsp; <a href="#" style="color:#bbb;text-decoration:underline" target="_blank">Privacy Policy</a>
</p>
</td>
</tr>
<tr>
<td style="padding: 0px 10px 10px;" align="center" valign="top" class="footerEmailInfo">
<p class="text" style="color:#bbb;font-family:'Open Sans',Helvetica,Arial,sans-serif;font-size:12px;font-weight:400;font-style:normal;letter-spacing:normal;line-height:20px;text-transform:none;text-align:center;padding:0;margin:0">If you have any quetions please contact us <a href="#" style="color:#bbb;text-decoration:underline" target="_blank">support@mail.com.</a>
<br> <a href="#" style="color:#bbb;text-decoration:underline" target="_blank">Unsubscribe</a> from our mailing lists</p>
</td>
</tr>
</table>
  `;
  return response;
};
