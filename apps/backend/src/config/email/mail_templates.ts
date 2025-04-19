export function generatePasswordResetEmail(name: string, resetLink: string): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8" />
          <title>Password Reset</title>
          <style>
            body {
              background-color: #0d1117;
              color: #c9d1d9;
              font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
              padding: 0;
              margin: 0;
            }
            .email-container {
              max-width: 600px;
              margin: 0 auto;
              padding: 40px;
              background-color: #161b22;
              border-radius: 10px;
              box-shadow: 0 2px 10px rgba(255, 255, 255, 0.05);
            }
            .button {
              display: inline-block;
              margin-top: 20px;
              background-color: #238636;
              color: #ffffff !important;
              padding: 12px 24px;
              border-radius: 6px;
              text-decoration: none;
              font-weight: bold;
            }
            .footer {
              text-align: center;
              color: #8b949e;
              font-size: 12px;
              margin-top: 40px;
            }
            @media only screen and (max-width: 620px) {
              .email-container {
                padding: 20px;
              }
            }
          </style>
        </head>
        <body>
          <div class="email-container">
            <h2>Hello ${name},</h2>
            <p>You recently requested to reset your password for your account.</p>
            <p>Click the button below to reset it. This link is valid for the next 15 minutes.</p>
            <a href="${resetLink}" class="button">Reset Password</a>
            <p>${resetLink}</p>
            <p>If you didn’t request a password reset, you can safely ignore this email.</p>
            <p>— The Team</p>
          </div>
          <div class="footer">
            <p>© ${new Date().getFullYear()} Your Company Name. All rights reserved.</p>
          </div>
        </body>
      </html>
    `;
  }