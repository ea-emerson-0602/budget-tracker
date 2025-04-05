# expenses/models.py
from django.db import models
from django.conf import settings
from datetime import date

class Expense(models.Model):
    CATEGORY_CHOICES = [
        ("Food", "Food"),
        ("Rent", "Rent"),
        ("Transport", "Transport"),
        ("Entertainment", "Entertainment"),
        ('Other', "Other")
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    description = models.TextField(blank=True, default='')
    date = models.DateField(default=date.today)  # Requires 'from datetime import date'
    class Meta:
        ordering = ['-date']
    
    def __str__(self):
        return f"{self.user} - {self.amount} ({self.category})"