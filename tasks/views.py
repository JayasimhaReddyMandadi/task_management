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
from django.contrib.auth.hashers import check_password
from .serializers import ProfileSerializer, UpdateUsernameSerializer, UpdatePasswordSerializer, AdminLoginSerializer
from .models import Profile
from rest_framework.decorators import api_view, permission_classes
from rest_framework.parsers import MultiPartParser, FormParser


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

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request):
        try:
            profile = Profile.objects.get(user=request.user)
            profile_photo_url = request.build_absolute_uri(profile.profile_photo.url) if profile.profile_photo else None
        except Profile.DoesNotExist:
            profile_photo_url = None

        return Response({
            'username': request.user.username,
            'email': request.user.email,
            'profile_photo': profile_photo_url
        })

class UpdateProfilePhotoView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        if 'profile_photo' not in request.FILES:
            return Response({'error': 'No image provided'}, status=status.HTTP_400_BAD_REQUEST)

        profile, created = Profile.objects.get_or_create(user=request.user)
        
        # Delete old photo if it exists
        if profile.profile_photo:
            profile.profile_photo.delete()
        
        profile.profile_photo = request.FILES['profile_photo']
        profile.save()

        return Response({
            'message': 'Profile photo updated successfully',
            'profile_photo': request.build_absolute_uri(profile.profile_photo.url)
        })

class UpdateUsernameView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UpdateUsernameSerializer(data=request.data)
        if serializer.is_valid():
            new_username = serializer.validated_data['username']
            
            # Check if username already exists
            if User.objects.filter(username=new_username).exclude(id=request.user.id).exists():
                return Response({'error': 'Username already taken'}, status=status.HTTP_400_BAD_REQUEST)
            
            request.user.username = new_username
            request.user.save()
            return Response({'message': 'Username updated successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = UpdatePasswordSerializer(data=request.data)
        if serializer.is_valid():
            if not check_password(serializer.validated_data['current_password'], request.user.password):
                return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
            
            request.user.set_password(serializer.validated_data['new_password'])
            request.user.save()
            return Response({'message': 'Password updated successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 # This is for admin login       
class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = AdminLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            login(request, user)
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'status': 'success',
                'message': 'Admin logged in successfully',
                'data': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'username': user.username,
                    'email':user.email,
                    'is_admin': user.is_staff or user.is_superuser
                }
            }, status=status.HTTP_200_OK)
        
        return Response({
            'status': 'error',
            'message': 'Invalid credentials',
            'errors': serializer.errors
        }, status=status.HTTP_401_UNAUTHORIZED)
    
class SuperuserDashboardView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        # Get regular users (excluding admins) with their tasks
        regular_users = User.objects.filter(is_superuser=False)
        users_data = []
        for user in regular_users:
            user_tasks = Task.objects.filter(user=user)
            tasks_data = [
                {
                    'id': task.id,
                    'title': task.title,
                    'description': task.description,
                    'status': task.status,
                    'deadline': task.deadline,
                    'created_at': task.created_at
                } for task in user_tasks
            ]
            
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'tasks': tasks_data
            })

        # Get admin users
        admin_users = User.objects.filter(is_superuser=True)
        admin_data = [
            {
                'id': admin.id,
                'username': admin.username,
                'email': admin.email
            } for admin in admin_users
        ]

        # Get all tasks
        all_tasks = Task.objects.all()
        tasks_list = [
            {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'priority':task.priority,
                'status': task.status,
                'deadline': task.deadline,
                'created_at': task.created_at,
                'user': task.user.username
            } for task in all_tasks
        ]

        return Response({
            'status': 'success',
            'data': {
                'user': {
                    'id': request.user.id,
                    'username': request.user.username,
                    'email': request.user.email,
                    'is_superuser': request.user.is_superuser,
                    'is_staff': request.user.is_staff,
                },
                'stats': {
                    'total_users': regular_users.count(),  # Only count regular users
                    'total_tasks': Task.objects.count(),
                    'total_admins': admin_users.count(),
                    'active_users': regular_users.filter(is_active=True).count(),
                },
                'users': users_data,  # Regular users with their tasks
                'admin_users': admin_data,  # List of admin users
                'all_tasks': tasks_list  # All tasks in the system
            }
        }, status=status.HTTP_200_OK)