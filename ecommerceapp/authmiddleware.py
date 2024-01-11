from .models import *
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from . serializers import *

class TokenMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if token:
            try:
                hash_token = token.replace("Bearer ", "")
                user = UserDetails.objects.get(token=hash_token)
                request.user_id = user.id
            except UserDetails.DoesNotExist:
                return JsonResponse({'error': 'Invalid token'}, status=401)

        response = self.get_response(request)
        return response


class UserExceptionError(Exception):
    def __init__(self,status=401,data={}):
        message="the user is not found"
        self.message=message
        self.status=status
        self.data=data
        super().__init__(message)
        
    def to_dict(self):
        return{
            'status':self.status,
            'data':self.data,
            'message':self.message
        }
        
        
class UsernameErrorException(Exception):
    def __init__(self,status=401,data={}):
        message="the username is not found"
        self.message=message
        self.status=status
        self.data=data
        super().__init__(message)
        
    def to_dict(self):
        return{
            'status':self.status,
            'data':self.data,
            'message':self.message
        }
        
        
class DataNotFoundError(Exception):
    def __init__(self,status=401,data={}):
        message="the credentials are not available"
        self.message=message
        self.status=status
        self.data=data
        super().__init__(message)
        
    def to_dict(self):
        return{
            'status':self.status,
            'data':self.data,
            'message':self.message
        }
        
        
class PermissionDeniedError(Exception):
    def __init__(self,status=204,data={}):
        message="Cannot delete. Products are associated with this category."
        self.message=message
        self.status=status
        self.data=data
        super().__init__(message)
        
    def to_dict(self):
        return{
            'status':self.status,
            'data':self.data,
            'message':self.message
        }
        
        
class OwnerPermissionDeniedError(Exception):
    def __init__(self,status=204,data={}):
        message="Unsuccessfull! you are not the owner'."
        self.message=message
        self.status=status
        self.data=data
        super().__init__(message)
        
    def to_dict(self):
        return{
            'status':self.status,
            'data':self.data,
            'message':self.message
        }
        
class SerializerDataErrors(Exception):
    def __init__(self,status=400,data={}):
        message="Data is missing'."
        self.message=message
        self.status=status
        self.data=data
        super().__init__(message)
        
    def to_dict(self):
        return{
            'status':self.status,
            'data':self.data,
            'message':self.message
        }
        
class TokenValidationFailedError(Exception):
    def __init__(self,status=400,data={}):
        message="Data is missing'."
        self.message=message
        self.status=status
        self.data=data
        super().__init__(message)
        
    def to_dict(self):
        return{
            'status':self.status,
            'data':self.data,
            'message':self.message
        }