from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import ListModelMixin, CreateModelMixin, UpdateModelMixin, \
    DestroyModelMixin, RetrieveModelMixin
from rest_framework_simplejwt.tokens import RefreshToken

from post.models import Post
from post.serializers import PostSerializers, UserFollowersPostSerializer, PostSavedSerializer, PostListSerializer, \
    PostLikeSerializer, PostSaveSerializer


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class PostApi(GenericViewSet, ListModelMixin, CreateModelMixin, UpdateModelMixin,
              DestroyModelMixin, RetrieveModelMixin):
    serializer_class = PostSerializers
    queryset = Post.objects.all()
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Post.objects.filter(user=user)


class AllUserPostApi(GenericViewSet, ListModelMixin):
    serializer_class = PostSerializers
    queryset = Post.objects.all()
    permission_classes = [IsAuthenticated]


class UserFollowersPostApi(GenericViewSet, ListModelMixin, CreateModelMixin, UpdateModelMixin,
                           DestroyModelMixin, RetrieveModelMixin):
    serializer_class = UserFollowersPostSerializer
    permission_classes = [IsAuthenticated]
    queryset = Post.objects.all()

    def get_queryset(self):
        posts = self.request.user.profile.followers.all()
        return Post.objects.filter(user__in=posts)


class UserPostLikeApi(GenericViewSet, ListModelMixin, CreateModelMixin, UpdateModelMixin,
                      DestroyModelMixin, RetrieveModelMixin):
    serializer_class = PostSerializers
    permission_classes = [IsAuthenticated]
    queryset = Post

    def get_queryset(self):
        user = self.request.user
        return user.users_likes.all()


class PostsSavedAPIView(GenericViewSet, ListModelMixin, CreateModelMixin, UpdateModelMixin,
                        DestroyModelMixin, RetrieveModelMixin):
    serializer_class = PostSavedSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return user.saved_posts.all()


class PostListView(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    serializer_class = PostListSerializer
    queryset = Post.objects.all()

    def list(self, request, *args, **kwargs):
        user = self.request.query_params.get('user_id')
        print(user)
        serializers = PostListSerializer(Post.objects.filter(user__id=user), many=True)
        return Response(serializers.data)


class PostLikeView(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    serializer_class = PostLikeSerializer
    queryset = Post.objects.all()
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        user = self.request.query_params.get('user_id')
        print(user)
        serializers = PostListSerializer(Post.objects.filter('likes'))
        return Response(serializers.data)


class PostSaveView(GenericViewSet, ListModelMixin, RetrieveModelMixin):
    serializer_class = PostSaveSerializer
    queryset = Post.objects.all()

    def list(self, request, *args, **kwargs):
        user = self.request.query_params.get('user_id')
        print(user)
        serializers = PostSaveSerializer(Post.objects.filter(saved_by__id=user), many=True)
        print(serializers)
        return Response(serializers.data)
