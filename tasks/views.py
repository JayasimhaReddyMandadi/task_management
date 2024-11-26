from django.contrib.auth import login, logout
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django_filters.rest_framework import DjangoFilterBackend
from .models import Task
from .serializers import TaskSerializer, UserRegisterSerializer, LoginSerializer
from .filters import TaskFilter


# Task List View: View tasks belonging to the logged-in user
class TaskListView(generics.ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = (DjangoFilterBackend,)
    filterset_class = TaskFilter
    ordering_fields = ['created_at', 'deadline']
    ordering = ['created_at']

    def get_queryset(self):
        # Restrict tasks to those belonging to the logged-in user
        return Task.objects.filter(user=self.request.user)


# Task Create View: Create a new task linked to the logged-in user
class TaskCreateView(generics.CreateAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        # Save the task with the current logged-in user
        serializer.save(user=self.request.user)


# Task Update View: Update tasks belonging to the logged-in user
class TaskUpdateView(generics.UpdateAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Restrict updates to tasks belonging to the logged-in user
        return Task.objects.filter(user=self.request.user)


# Task Delete View: Delete tasks belonging to the logged-in user
class TaskDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Restrict deletions to tasks belonging to the logged-in user
        return Task.objects.filter(user=self.request.user)


# Register View: Create a new user
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]


# Login View: Log in a user
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            login(request, user)
            return Response({"message": "Logged in successfully!"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Logout View: Log out the user
class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logout(request)
        return Response({"message": "Logged out successfully!"}, status=status.HTTP_200_OK)
