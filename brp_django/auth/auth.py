from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import AllowAny
from rest_framework import status
from auth.serializers import UserRegistrationSerailizer, SendResetPasswordEmailViewSerailizer, ChangePasswordViewSerailizer, ResetPasswordViewSerializer


class UserRegisterationView(CreateAPIView):
    serializer_class = UserRegistrationSerailizer
    permission_classes = [AllowAny]
    
    def post(self,request, *args, **kwargs):
        serializer = self.serializer_class(data =request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message":"Registration successfull!"},status=status.HTTP_201_CREATED)
        return Response({"message":"Registration Failed!"},status=status.HTTP_400_BAD_REQUEST)


class UserLoginTokenView(ObtainAuthToken):
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        if user.department:
            department_dict = {
                "id":user.department.id,
                "name":user.department.name
            }
        else:
            department_dict = None

        if  user.groups.first() != None:
            group = user.groups.first().name
        else:
            group = None
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'username': user.username,
            'group':group,
            'department': department_dict,
            'email':user.email if user.email else None 
        }, status=status.HTTP_200_OK)


class ChangePasswordView(CreateAPIView):
    serializer_class = ChangePasswordViewSerailizer
    
    def post(self,request, *args, **kwargs):
        serializer = self.serializer_class(data= request.data, context={"user":request.user})
        serializer.is_valid(raise_exception=True)
        return Response({"message":"Password Changed successfully!!!!!!!!"})
                   

class SendResetPasswordEmailView(CreateAPIView):
    serializer_class = SendResetPasswordEmailViewSerailizer
    permission_classes = [AllowAny]
    
    def post(self,request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message":"Password Reset Email Send Successfully!!!!!!!!"})


class ResetPasswordView(CreateAPIView):
    serializer_class = ResetPasswordViewSerializer
    permission_classes = [AllowAny]
    
    def post(self,request, uid, token, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={"uid":uid, "token":token})
        serializer.is_valid(raise_exception=True)
        return Response({"message":"Password Reset Successfully!!!!!!!!"})
