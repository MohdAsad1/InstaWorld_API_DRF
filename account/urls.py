from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from account import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()

router.register(r'register', views.UserRegister, basename='register'),
router.register(r'login', views.UserLogIn, basename='login'),
router.register(r'change-password', views.UserChangePassword, basename='change_password'),
router.register(r'delete-user', views.DeleteUser, basename='delete_user'),
router.register(r'user', views.UserView, basename='user'),


urlpatterns = [
    path('', include(router.urls))

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
