from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('account/', include('account.urls')),
    path('post/', include('post.urls')),
    path('story/', include('story.urls')),
]