from django.urls import path
from .views import *

urlpatterns = [
    # path('expenses/', ExpenseViewSet.as_view(), name='expenses'),
    
    path("expenses/", ExpenseViewSet.as_view(), name="expense-list"),
]