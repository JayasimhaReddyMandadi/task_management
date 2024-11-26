# tasks/filters.py

import django_filters
from django.contrib.auth.models import User
from .models import Task
from django_filters import DateFilter

class TaskFilter(django_filters.FilterSet):
    # Filter by status
    status = django_filters.ChoiceFilter(choices=Task.STATUS_CHOICES, lookup_expr='iexact')
    
    # Filter by priority
    priority = django_filters.ChoiceFilter(choices=Task.PRIORITY_CHOICES, lookup_expr='iexact')

    # Filter by description (partial match)
    description = django_filters.CharFilter(field_name='description', lookup_expr='icontains')

    # Filter by title (partial match)
    title = django_filters.CharFilter(field_name='title', lookup_expr='icontains')

    # Filter by user (assumes user is related to Task, one-to-many relation)
    user = django_filters.ModelChoiceFilter(queryset=User.objects.all(), required=False)

    # Filter by date range
    start_date = DateFilter(field_name='deadline', lookup_expr='gte')  # Greater than or equal to
    end_date = DateFilter(field_name='deadline', lookup_expr='lte')  # Less than or equal to

    class Meta:
        model = Task
        fields = ['status', 'priority', 'description', 'title', 'user', 'start_date', 'end_date']
