from rest_framework import serializers
from .models import ContactMessage


class ContactMessageSerializer(serializers.ModelSerializer):
    """
    Serializer for ContactMessage model.
    Handles validation and serialization of contact form submissions.
    """

    class Meta:
        model = ContactMessage
        fields = ['id', 'first_name', 'last_name', 'email', 'message', 'heard_about', 'created_at']
        read_only_fields = ['id', 'created_at']

    def validate_email(self, value):
        """Validate email format."""
        if not value:
            raise serializers.ValidationError("Email address is required.")
        return value.lower().strip()

    def validate_first_name(self, value):
        """Validate first name."""
        if not value or not value.strip():
            raise serializers.ValidationError("First name is required.")
        return value.strip()

    def validate_message(self, value):
        """Validate message content."""
        if not value or not value.strip():
            raise serializers.ValidationError("Message cannot be empty.")
        if len(value.strip()) < 10:
            raise serializers.ValidationError("Message must be at least 10 characters long.")
        return value.strip()

    def validate_last_name(self, value):
        """Trim last name if provided."""
        if value:
            return value.strip()
        return value

    def validate_heard_about(self, value):
        """Trim heard_about if provided."""
        if value:
            return value.strip()
        return value
