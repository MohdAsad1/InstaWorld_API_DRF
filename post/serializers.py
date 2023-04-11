from django.contrib.auth.models import User
from rest_framework import serializers

from account.models import UserProfile
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
                   'groups', 'user_permissions', "email"]


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
        print(images_data)

        post = Post.objects.create(**validated_data, user=self.context['request'].user)
        print(post)
        images = []
        videos = []

        for image_data in images_data:
            image = Image.objects.create(image=image_data)
            images.append(image)
        post.images.set(images)

        for video_data in videos_data:
            video = Video.objects.create(video=video_data)
            videos.append(video)
        post.videos.set(videos)

        print(post)

        return post


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('image',)


class PostLikeSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        exclude = ['likes', 'comments', 'saved_by']


class UserFollowersPostSerializer(serializers.ModelSerializer):
    user_profile = UserProfileSerializer(source='user.userprofile', read_only=True)
    has_liked = serializers.SerializerMethodField()
    has_saved = serializers.SerializerMethodField()
    images = ImageSerializer(many=True, required=False)
    videos = VideoSerializer(many=True, required=False)
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        fields = "__all__"

    def get_has_liked(self, obj: Post) -> bool:
        user: User = self.context["request"].user
        return user.is_authenticated and user.users_likes.filter(pk=obj.pk).exists()

    def get_has_saved(self, obj: Post) -> bool:
        user: User = self.context["request"].user
        return user.is_authenticated and user.saved_posts.filter(pk=obj.pk).exists()


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


class PostSaveSerializer(serializers.ModelSerializer):
    images = ImageSerializer(many=True, required=False)
    videos = VideoSerializer(many=True, required=False)
    user = UserSerializer(read_only=True)

    class Meta:
        model = Post
        exclude = ['likes', 'comments', 'saved_by']


class PostCommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    comments = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = ('user', 'comments', 'post_description')

    def get_comments(self, obj):
        comments = obj.comments.all().values('comment', 'created_at', 'user__username', 'user__userprofile__image')
        return [
            {
                'comment': comment['comment'],
                'created_at': comment['created_at'],
                'user': {
                    'username': comment['user__username'],
                    'profile_pic': comment['user__userprofile__image'] if comment[
                        'user__userprofile__image'] else None
                }
            }
            for comment in comments
        ]


class SearchFeedPostSerializer(serializers.ModelSerializer):
    images = ImageSerializer(many=True, required=False)

    class Meta:
        model = Post
        fields = ["id", "images"]


class CreateCommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Comment
        fields = ('comment', 'user')
