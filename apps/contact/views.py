from rest_framework import generics, status
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
import logging

from .models import ContactMessage
from .serializers import ContactMessageSerializer

logger = logging.getLogger(__name__)


class ContactMessageView(generics.CreateAPIView):
    """
    API endpoint for handling contact form submissions.
    
    - Accepts POST requests from unauthenticated users
    - Validates and saves contact messages
    - Sends admin notification email
    - Sends auto-reply confirmation email to user
    - Returns 201 Created with message data
    
    POST /api/v1/contact/
    """
    queryset = ContactMessage.objects.all()
    serializer_class = ContactMessageSerializer
    permission_classes = []  # Allow unauthenticated access
    authentication_classes = []  # No authentication required

    def create(self, request, *args, **kwargs):
        """
        Handle POST request to create contact message.
        Sends emails after successful creation.
        """
        # Validate and save the message
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        contact_message = serializer.save()

        # Extract data for emails
        first_name = contact_message.first_name
        last_name = contact_message.last_name
        full_name = contact_message.full_name
        user_email = contact_message.email
        message_text = contact_message.message
        heard_about = contact_message.heard_about or "Not specified"

        # Send admin notification email
        try:
            admin_subject = f"New Contact Message from {full_name}"
            admin_message = (
                f"You have received a new contact form submission.\n\n"
                f"From: {full_name}\n"
                f"Email: {user_email}\n"
                f"Heard about us: {heard_about}\n\n"
                f"Message:\n{message_text}\n\n"
                f"---\n"
                f"This is an automated notification from WasteWorth Contact Form."
            )
            
            send_mail(
                subject=admin_subject,
                message=admin_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=['info@wasteworth.com'],
                fail_silently=True,
            )
            logger.info(f"Admin notification email sent for contact from {user_email}")
        except Exception as e:
            logger.error(f"Failed to send admin notification email: {str(e)}")

        # Send auto-reply email to user
        try:
            user_subject = "Thanks for contacting WasteWorth"
            user_message = (
                f"Hello {first_name},\n\n"
                f"Thank you for reaching out to WasteWorth. "
                f"We've received your message and our support team will get back to you shortly.\n\n"
                f"Your message:\n\"{message_text}\"\n\n"
                f"We typically respond within 24-48 hours during business days.\n\n"
                f"Best regards,\n"
                f"The WasteWorth Team\n\n"
                f"---\n"
                f"This is an automated confirmation email. Please do not reply to this email."
            )
            
            send_mail(
                subject=user_subject,
                message=user_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user_email],
                fail_silently=True,
            )
            logger.info(f"Auto-reply email sent to {user_email}")
        except Exception as e:
            logger.error(f"Failed to send auto-reply email to {user_email}: {str(e)}")

        # Return success response
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )
