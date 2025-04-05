# expenses/views.py
from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend
import django_filters
from .models import Expense
from .serializers import ExpenseSerializer
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination

class ExpenseFilter(django_filters.FilterSet):
    date__gte = django_filters.DateFilter(field_name='date', lookup_expr='gte')
    date__lte = django_filters.DateFilter(field_name='date', lookup_expr='lte')

    class Meta:
        model = Expense
        fields = ['category', 'date__gte', 'date__lte']

class ExpenseViewSet(viewsets.ModelViewSet):
    serializer_class = ExpenseSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_class = ExpenseFilter  # Use custom filter class
    ordering_fields = ['date', 'amount']
    ordering = ['-date']  # Default ordering
    pagination_class = PageNumberPagination

    def get_queryset(self):
        """Base queryset with user isolation"""
        return self.request.user.expense_set.all()

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        
        # Get ordering parameter correctly
        ordering = self.request.query_params.get('ordering', '-date')
        if ordering:
            # Split comma-separated ordering fields
            ordering_fields = ordering.strip().split(',')
            queryset = queryset.order_by(*ordering_fields)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    def get_paginated_response(self, data):
        response = super().get_paginated_response(data)
        response.data.update({
            'total_pages': self.paginator.page.paginator.num_pages,
            'current_page': self.paginator.page.number,
        })
        return response

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user:
            return Response({"error": "Not authorized"}, status=403)
        return super().update(request, *args, **kwargs)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user != request.user:
            return Response({"error": "Not authorized"}, status=403)
        return super().destroy(request, *args, **kwargs)