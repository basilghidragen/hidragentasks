from .models import *
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from . serializers import *
from .validators import validate_data
import  json 
from urllib.parse import urljoin

class TokenMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.META.get('HTTP_AUTHORIZATION')
        if token:
            try:
                hash_token = token.replace("Bearer ", "")
                user = UserDetails.objects.get(token=hash_token)
                # request.user_id = user.id
                request.user_id = 4

            except UserDetails.DoesNotExist:
                return JsonResponse({'error': 'Invalid token'}, status=401)

        response = self.get_response(request)
        return response

class ApiValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        try:
            base_url = 'https://127.0.0.1:8000/'
            end_point = request.path
            api_url = urljoin(base_url,end_point)
            response = requests.get(api_url, params=params)

            if response.status_code == 200:
                # Parse the JSON response
                api_data = response.json()
                return api_data
            else:
                print(f"Error: {response.status_code}")
                content_type = request.headers.get('Content-Type')
                print(content_type)
                sd=request.data
                print(sd)
            try:
                json_data = json.loads(request.body.decode('utf-8'))
                
            except Exception as e:
                print(f"Error decoding JSON: {e}")
            print('i want to try')
            files = request.FILES
            data = {**json_data, **files}
            validate_data(data)
            response = self.get_response(request)
            return response

        except Exception as e:
            error_message = str(e)
            print('error_message',error_message)
            return JsonResponse({'error': error_message}, status=400)

        

    