from validator import validate


def validate_data(data):
    validation_rules = {
        "product_name":"required",
        "image": "required",
        "category": "required"
        
    }

    try:
        print('try loaded')
        result, _, errors = validate(data, validation_rules, return_info=True)
        print('try decoded')
        print('result',result) 
        print('errors',errors)
        if result:
            return result, None
        error_messages = {field: error[0] for field, error in errors.items()}
        # print('error_messages',error_messages)
        return result, error_messages

    except Exception as e:  
        error_message = str(e)
        print('error_message', error_message)
        return False, {'error': error_message}
    
    
    
    
import requests

def get_api_data(api_url, params=None):
    try:
        response = requests.get(api_url, params=params)

        if response.status_code == 200:
            # Parse the JSON response
            api_data = response.json()
            return api_data
        else:
            print(f"Error: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

# Example usage:
api_url = "https://api.example.com/data"
api_params = {'param1': 'value1', 'param2': 'value2'}

result = get_api_data(api_url, params=api_params)