from django.contrib.auth.models import User
from rest_framework import serializers

from post.models import Post, Image, Video, Comment


class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ('id', 'image')


class VideoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Video
        fields = ('id', 'video')


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ['password', 'is_active', 'is_staff', 'last_login', 'is_superuser', 'date_joined',
                   'groups', 'user_permissions']


class PostSerializers(serializers.ModelSerializer):
    likes_count = serializers.SerializerMethodField()
    comment_count = serializers.SerializerMethodField()
    has_liked = serializers.SerializerMethodField()
    has_saved = serializers.SerializerMethodField()
    images = ImageSerializer(many=True, required=False)
    videos = VideoSerializer(many=True, required=False)
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        exclude = ['likes', 'comments', 'saved_by']

    def get_comment_count(self, obj: Post):
        return obj.comments.count()

    def get_likes_count(self, obj: Post):
        return obj.likes.count()

    def get_has_liked(self, obj: Post) -> bool:
        user: User = self.context["request"].user
        return user.is_authenticated and user.users_likes.filter(pk=obj.pk).exists()

    def get_has_saved(self, obj: Post) -> bool:
        user: User = self.context["request"].user
        return user.is_authenticated and user.saved_posts.filter(pk=obj.pk).exists()

    def create(self, validated_data):
        images_data = self.context.get('request').FILES.getlist('images', [])
        videos_data = self.context.get('request').FILES.getlist('videos', [])
        comment_data = self.initial_data.getlist('comments', [])

        post = Post.objects.create(**validated_data, user=self.context['request'].user)

        images = []
        videos = []
        comments = []

        for image_data in images_data:
            img = Image.objects.create(image=image_data)
            images.append(img)
        post.images.set(images)

        for video_data in videos_data:
            vid = Video.objects.create(video=video_data)
            videos.append(vid)
        post.videos.set(videos)

        for com_data in comment_data:
            com = Comment.objects.create(text=com_data, user_id=self.context["request"].user.id)
            comments.append(com)
        post.comments.set(comments)
        post.save()

        return post


class UserFollowersPostSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        fields = "__all__"


class UserPostLikeSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        fields = "__all__"


class CommentSerializer(PostSerializers):
    class Meta:
        model = Post
        fields = "__all__"


class PostListSerializer(serializers.ModelSerializer):
    images = ImageSerializer(many=True, required=False)
    videos = VideoSerializer(many=True, required=False)
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        exclude = ['likes', 'comments', 'saved_by']


class PostSavedSerializer(PostSerializers):
    user = UserSerializer(read_only=True)
    pass


class PostLikeSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        exclude = ['likes', 'comments', 'saved_by']


class PostSaveSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        exclude = ['likes', 'comments', 'saved_by']



#utils
import os

from rest_framework_simplejwt.tokens import RefreshToken


def user_upload_path(instance, filename):

    username = instance.user.username
    ext = filename.split('.')[-1]
    if ext in ['jpg', 'jpeg', 'png', 'gif']:
        folder = 'images'
    elif ext in ['mp4', 'avi', 'mov', 'mkv']:
        folder = 'videos'
    else:
        raise ValueError('Unsupported file format')
    return os.path.join(username, folder, filename)


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
