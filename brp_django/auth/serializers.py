from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, smart_str, DjangoUnicodeDecodeError
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import serializers
from auth.utils import send_reset_mail , validate_password


User = get_user_model()
                
    
class UserRegistrationSerailizer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'confirm_password','groups','email']
        extra_kwargs = {
            'id': {'read_only': True},
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.pop('confirm_password')
        if password != confirm_password:
            raise ValidationError("Password and confirm password doesn't match")
        return attrs
    
    def create(self,validated_data):
        user = User(
            username = validated_data['username'] 
        )
        user.set_password(validated_data['password'])
        user.save()

        # Add user to specified groups if any
        groups = validated_data.get('groups', [])
        user.groups.set(groups)
        return user
    
    
class ChangePasswordViewSerailizer(serializers.Serializer):
    old_password = serializers.CharField(max_length=100, style={'input_type':'password'}, write_only=True)
    new_password = serializers.CharField(max_length=100, style={'input_type':'password'}, write_only=True)
    confirm_password = serializers.CharField(max_length=100, style={'input_type':'password'}, write_only=True)
    
    def validate(self, attrs):
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        user = self.context.get('user')
        validate_password(old_password, new_password, confirm_password, user)
        user.set_password(new_password)
        user.save()
        return attrs
    

class SendResetPasswordEmailViewSerailizer(serializers.Serializer):
    email = serializers.EmailField(max_length=100)
    
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.filter(email=email).first()
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = f'{settings.DJANGO_HOSTS}/forgot-password/reset/?uid={uid}&token={token}'
            send_reset_mail("Reset Link", link,[email])
        
            return attrs 
        else:
            raise serializers.ValidationError("Email does not exists")
       
       
class ResetPasswordViewSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, style={'input_type': 'password'}, write_only=True)
    confirm_password = serializers.CharField(max_length=100, style={'input_type': 'password'}, write_only=True)
    
    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        uid = self.context.get("uid")
        token = self.context.get("token")
        
        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")
        
        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("The token is invalid or has expired.")
            user.set_password(password)
            user.save()
            return attrs
            
        except (User.DoesNotExist, DjangoUnicodeDecodeError):
            raise serializers.ValidationError("Invalid token or user.")
