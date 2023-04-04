from django.contrib.auth import authenticate
from django.db.models import Q
from rest_framework import serializers, generics
from rest_framework.authentication import BasicAuthentication
from rest_framework.mixins import CreateModelMixin, DestroyModelMixin, UpdateModelMixin, ListModelMixin
from rest_framework.permissions import IsAdminUser
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from account.serializers import UserRegisterSerializer, UserLogInSerializer, UserChangePasswordSerializer, \
    DeleteUserSerializer, ProfileSerializer, UserSearchSerializer, FollowingSerializer, FollowersSerializer, \
    UserProfileOTPSerializer
from post.utils import get_tokens_for_user
from django.contrib.auth.models import User
from rest_framework import mixins, status
from rest_framework.viewsets import GenericViewSet
from rest_framework.response import Response
from .models import UserProfile
from .serializers import VerifyOTPSerializer

from .serializers import UserSerializer

from rest_framework.views import APIView


class UserRegister(GenericViewSet, CreateModelMixin):
    """View to register user"""
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            user, user_profile = serializer.create(serializer.validated_data)
            user_token = get_tokens_for_user(user)
            return Response({'token': user_token,
                             "message": "User created successfully",
                             "user_profile_id": user_profile.id},
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLogIn(GenericViewSet, CreateModelMixin):
    """View for login user"""
    queryset = User.objects.all()
    serializer_class = UserLogInSerializer
    http_method_names = ['post']

    def create(self, request, *args, **kwargs):

        data = request.data
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            username_or_email = request.data.get('username')
            password = request.data.get('password')
            user = User.objects.filter(Q(email=username_or_email) | Q(username=username_or_email)).first()
            print(user)
            # user = authenticate(**data)
            if not user:
                raise serializers.ValidationError("No such user found. Register First!")
            if user.check_password(password):
                user_token = get_tokens_for_user(user)

                return Response({'token': user_token,
                                 "data": serializer.data,
                                 'message': "Successfully Logged In",
                                 }, status=status.HTTP_200_OK)
        return Response({
            'data': serializer.errors}, status=status.HTTP_404_NOT_FOUND)


class UserChangePassword(GenericViewSet, UpdateModelMixin):
    """View to change password of the user"""
    queryset = User
    serializer_class = UserChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        queryset = self.request.user
        return queryset

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("password")):
                return Response({"password": "Wrong password."}, status=status.HTTP_400_BAD_REQUEST)
            if request.data.get("new_password") != request.data.get("confirm_password"):
                return Response({"password": "Password and confirm password does not match!"},
                                status=status.HTTP_400_BAD_REQUEST)
            self.object.set_password(request.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteUser(GenericViewSet, DestroyModelMixin):
    """View for deleting user by admin user only"""
    queryset = User.objects.all()
    serializer_class = DeleteUserSerializer
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAdminUser]


class UserView(GenericViewSet, ListModelMixin):
    """View to get post of the users followed by user"""
    queryset = User.objects.all()
    serializer_class = UserSerializer


class ProfileAPI(GenericViewSet, mixins.ListModelMixin, mixins.CreateModelMixin, mixins.RetrieveModelMixin,
                 mixins.UpdateModelMixin, mixins.DestroyModelMixin):
    serializer_class = ProfileSerializer
    queryset = UserProfile.objects.all()


class FollowerViewSet(GenericViewSet, ListModelMixin):
    serializer_class = FollowersSerializer
    queryset = UserProfile.objects.all()
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        profile = UserProfile.objects.get(user=request.user)
        serializer = self.get_serializer(profile)
        return Response(serializer.data)


class FollowingViewSet(GenericViewSet, ListModelMixin):
    serializer_class = FollowingSerializer
    queryset = UserProfile.objects.all()
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        profile = UserProfile.objects.get(user=request.user)
        serializer = self.get_serializer(profile)
        return Response(serializer.data)


class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user if request.user.is_authenticated else None)
            user = serializer.validated_data['user']
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                    'message': 'OTP verified successfully and account activated!'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'OTP verified successfully!'
                }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserSearchView(GenericViewSet):
    serializer_class = UserSearchSerializer

    def list(self, request, *args, **kwargs):
        search = request.query_params.get('search')
        if search:
            queryset = User.objects.filter(Q(username__icontains=search) | Q(first_name__icontains=search) |
                                           Q(last_name__icontains=search))
        else:
            return Response({"message": "No user found"})
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class GenerateOTPView(generics.GenericAPIView, mixins.UpdateModelMixin):
    serializer_class = UserProfileOTPSerializer
    queryset = UserProfile.objects.all()

    def patch(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        user_profile = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        otp = serializer.generate_otp(user_profile, serializer.validated_data)
        user_profile_serializer = UserProfileOTPSerializer(user_profile)

        return Response({'message': 'OTP Sent successfully'},
                        status=status.HTTP_200_OK)
