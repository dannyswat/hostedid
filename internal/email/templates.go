package email

import "fmt"

// VerificationEmailHTML returns the HTML body for a verification OTP email.
func VerificationEmailHTML(otp string, appName string, ttlMinutes int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verify your email</title>
</head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background-color:#f4f5f7;">
<table width="100%%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f7;padding:40px 0;">
<tr><td align="center">
<table width="480" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
  <tr><td style="padding:32px 40px 24px;text-align:center;">
    <h1 style="margin:0;font-size:24px;color:#1a1a2e;">Verify your email</h1>
  </td></tr>
  <tr><td style="padding:0 40px;">
    <p style="margin:0 0 24px;font-size:15px;color:#4a4a68;line-height:1.6;">
      Thanks for signing up for <strong>%s</strong>! Use the verification code below to complete your registration.
    </p>
  </td></tr>
  <tr><td style="padding:0 40px;text-align:center;">
    <div style="display:inline-block;background-color:#f0f0ff;border:2px dashed #6c63ff;border-radius:8px;padding:16px 40px;margin:0 0 24px;">
      <span style="font-family:'Courier New',monospace;font-size:36px;font-weight:bold;letter-spacing:8px;color:#1a1a2e;">%s</span>
    </div>
  </td></tr>
  <tr><td style="padding:0 40px 32px;">
    <p style="margin:0;font-size:13px;color:#8888a0;line-height:1.5;">
      This code expires in <strong>%d minutes</strong>. If you didn't create an account, you can safely ignore this email.
    </p>
  </td></tr>
  <tr><td style="padding:16px 40px;background-color:#f9f9fc;border-top:1px solid #eeeef2;">
    <p style="margin:0;font-size:12px;color:#aaaabc;text-align:center;">
      &copy; %s &mdash; This is an automated message, please do not reply.
    </p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>`, appName, otp, ttlMinutes, appName)
}

// VerificationEmailText returns the plain-text body for a verification OTP email.
func VerificationEmailText(otp string, appName string, ttlMinutes int) string {
	return fmt.Sprintf(`Verify your email

Thanks for signing up for %s! Use the verification code below to complete your registration.

Your verification code: %s

This code expires in %d minutes. If you didn't create an account, you can safely ignore this email.

- %s`, appName, otp, ttlMinutes, appName)
}
