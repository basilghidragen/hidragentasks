from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import *
from django.http import Http404
import hashlib
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import MultiPartParser, FormParser  
import jwt
from datetime import datetime, timedelta

# Create your views here.

# User class
class UserLoginView(APIView):
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        user = UserDetails.objects.filter(username=username).first()

        if user and user.password == hashed_password:
            payload = {
                'user_id': user.id,
                'username': user.username,
                'exp': datetime.utcnow() + timedelta(days=1)
            }
            access_token = jwt.encode(payload, 'your_secret_key', algorithm='HS256')

            user.token = access_token
            user.save(update_fields=['token'])
            message='login successfull'
            return Response({'access_token': access_token,'message':message}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
          
class UserLogoutView(APIView):

    def post(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        print(token)
        try:
            user = UserDetails.objects.get(token=token)
        except UserDetails.DoesNotExist:
            return Response({'error': 'User not found for this token'}, status=status.HTTP_404_NOT_FOUND)
        user.token = None
        user.save(update_fields=['token'])
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)


class UserDetailsAPIView(APIView):
    
    def get_userdetails(self, pk):
        try:
            return UserDetails.objects.get(pk=pk)
        except UserDetails.DoesNotExist:
            raise Http404
        
    def get(self, request):
        users = UserDetails.objects.all()
        serializer = UserDetailsSerializer(users, many=True)
        return Response(serializer.data)
        
    def post(self, request):
        serializer = UserDetailsSerializer(data=request.data)
        if serializer.is_valid():
            #SHA256
            password = serializer.validated_data['password']
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            serializer.validated_data['password'] = hashed_password
            serializer.save()
            message = 'user created successfully'
            response_data = {
            'message': message,
            'data': serializer.data,
        }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        user = self.get_userdetails(pk)
        serializer = UserDetailsSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        user = self.get_userdetails(pk)
        user.delete()
        message='data deleted successfully'
        message={'message':message}
        return Response(message,status=status.HTTP_204_NO_CONTENT)

# Category Class

class CategoryAPIView(APIView):
    
    def get_category(self, pk):
        try:
            return Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            raise Http404
        
    def get(self, request):
        category = Category.objects.all()
        serializer = CategorySerializer(category, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        object = self.get_category(pk)
        serializer = CategorySerializer(object, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        category = self.get_category(pk)
        related_products = Products.objects.filter(category=category)
        if related_products.exists():
            message = {'message': 'Cannot delete. Products are associated with this category.'}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)
        
        category.delete()
        message='data deleted successfully'
        message={'message':message}
        return Response(message,status=status.HTTP_204_NO_CONTENT)
    
# Product Class

class ProductsAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser]
    
    def get_products(self, pk):
        try:
            return Products.objects.get(pk=pk)
        except Products.DoesNotExist:
            raise Http404
        
    def get(self, request):
        products = Products.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        user_id=getattr(request,'user_id',None)
        request.data['user'] = user_id

        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        try:
            product = Products.objects.get(pk=pk)

        except Products.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        if product.user == request.user:
            serializer = ProductSerializer(product, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            message = {'message': 'Cannot update you are not the owner'}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        product = self.get_products(pk)
        if product.user == request.user:
            product.delete()
            message='data deleted successfully'
            message={'message':message}
            return Response(message,status=status.HTTP_204_NO_CONTENT)
        else:
            message = {'message': 'Cannot update you are not the owner'}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

