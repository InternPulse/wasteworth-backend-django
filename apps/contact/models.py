from django.db import models


class ContactMessage(models.Model):
    """
    Model to store contact form submissions from users.
    Used for general inquiries, support requests, and feedback.
    """
    class Meta:
        db_table = 'contact_messages'
        ordering = ['-created_at']

    first_name = models.CharField(max_length=100, help_text="User's first name")
    last_name = models.CharField(max_length=100, blank=True, help_text="User's last name (optional)")
    email = models.EmailField(help_text="User's email address")
    message = models.TextField(help_text="User's message or inquiry")
    heard_about = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="How the user heard about WasteWorth (e.g., Instagram, Facebook, Friend)"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Contact from {self.first_name} {self.last_name} ({self.email}) - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

    @property
    def full_name(self):
        """Returns user's full name."""
        if self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name
