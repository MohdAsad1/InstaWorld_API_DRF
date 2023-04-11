from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from account import views
from rest_framework.routers import DefaultRouter

from account.views import VerifyOTPView, ProfileAPI, GenerateOTPView, ForgotPasswordOTPView, \
    UserProfileIdView, ForgotPassword, UserLogoutView

router = DefaultRouter()

router.register(r'register', views.UserRegister, basename='register'),
router.register(r'login', views.UserLogIn, basename='login'),
router.register(r'change-password', views.UserChangePassword, basename='change_password'),
router.register(r'delete-user', views.DeleteUser, basename='delete_user'),
router.register(r'user', views.UserView, basename='user'),
router.register(r'search-user', views.UserSearchView, basename='search_user'),
router.register(r'profile', ProfileAPI, basename='profile')
router.register('get_followers_list', views.FollowerViewSet, basename='get_followers_list')
router.register('get_following_list', views.FollowingViewSet, basename='get_following_list')
router.register('forgot_password', ForgotPassword, basename='forgot_password')


urlpatterns = [
    path('verify_otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('generate_otp/<int:pk>/', GenerateOTPView.as_view(), name='generate_otp'),
    path('forgot_password_send_otp/<int:pk>/', ForgotPasswordOTPView.as_view(), name='forgot_password_send_otp'),
    path('forget_password_username/', UserProfileIdView.as_view(), name='forget_password_username'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('', include(router.urls))
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
