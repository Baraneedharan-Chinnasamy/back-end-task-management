import smtplib

EMAIL_USER = "advarttaskmanagement@gmail.com"
EMAIL_PASS = "xsunmuajhlppmqsh"  # paste app password here

try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_USER, EMAIL_PASS)
        print("✅ Login successful! App password is correct.")
except smtplib.SMTPAuthenticationError as e:
    print("❌ Authentication failed:", e.smtp_error.decode())
except Exception as e:
    print("❌ Some other error occurred:", e)