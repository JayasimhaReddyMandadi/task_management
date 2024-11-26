# tasks/models.py

from django.contrib.auth.models import User
from django.db import models

class Task(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    STATUS_CHOICES = [
        ('yet-to-start', 'Yet to start'),
        ('in-progress', 'In progress'),
        ('completed', 'Completed'),
        ('on_hold', 'On Hold'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tasks')  # Link task to a user
    title = models.CharField(max_length=255)
    description = models.TextField()
    priority = models.CharField(max_length=6, choices=PRIORITY_CHOICES, default='low')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='yet-to-start')
    deadline = models.DateField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']  # Default ordering by creation date (newest first)
        indexes = [
            models.Index(fields=['user', 'status']),  # Add index for common queries
            models.Index(fields=['deadline']),
        ]

    def __str__(self):
        return self.title
