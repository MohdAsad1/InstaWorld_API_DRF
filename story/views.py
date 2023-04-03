from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import CreateModelMixin, ListModelMixin, UpdateModelMixin

from .models import Story
from django.utils import timezone

from .serializers import StorySerializer, ArchiveStorySerializer, HighlightStorySerializer


class StoryView(GenericViewSet, CreateModelMixin, ListModelMixin):
    queryset = Story
    serializer_class = StorySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def get_queryset(self):
        now = timezone.now()
        Story.objects.filter(created_at__lte=now - timezone.timedelta(minutes=60)).update(is_archived=True)

        queryset = Story.objects.filter(user=self.request.user, created_at__lt=now, is_archived=False)
        return queryset


class ArchiveStoryView(GenericViewSet, CreateModelMixin, ListModelMixin):
    queryset = Story
    serializer_class = ArchiveStorySerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def get_queryset(self):
        now = timezone.now()
        Story.objects.filter(created_at__lte=now - timezone.timedelta(minutes=60)).update(is_archived=True)

        queryset = Story.objects.filter(user=self.request.user, is_archived=True)
        return queryset


class HighlightStoryView(GenericViewSet, ListModelMixin):
    queryset = Story
    serializer_class = HighlightStorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Story.objects.filter(is_highlighted=True)


