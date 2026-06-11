import ssl
import smtplib
from django.core.mail.backends.smtp import EmailBackend

class CustomEmailBackend(EmailBackend):
    """
    Custom SMTP Email Backend to allow lower security levels (SECLEVEL=1)
    for older SMTP servers that use small DH keys.
    """
    def open(self):
        if self.connection:
            return False
        
        try:
            # Create a custom SSL context
            context = ssl.create_default_context()
            # Lower security level to 1 to avoid "DH_KEY_TOO_SMALL" error
            context.set_ciphers('DEFAULT@SECLEVEL=1')
            
            # Manually initialize the connection
            self.connection = self.connection_class(self.host, self.port, timeout=self.timeout)
            
            # Perform STARTTLS if requested
            if self.use_tls:
                self.connection.ehlo()
                self.connection.starttls(context=context)
                self.connection.ehlo()
            
            # Login if credentials are provided
            if self.username and self.password:
                self.connection.login(self.username, self.password)
            
            return True
        except Exception:
            if not self.fail_silently:
                raise
            return False
