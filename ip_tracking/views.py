from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit

# Create your views here.
@csrf_exempt
@ratelimit(key='ip', rate='10/m', method='POST', block=True)   # Authenticated users
@ratelimit(key='ip', rate='5/m', method='POST', block=True)    # Anonymous users
def login_view(request):
    """
    Example login view protected by IP-based rate limiting.
    - Authenticated users: 10 requests/min
    - Anonymous users: 5 requests/min
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    username = request.POST.get('username')
    password = request.POST.get('password')

    user = authenticate(username=username, password=password)
    if user is not None:
        login(request, user)
        return JsonResponse({'message': 'Login successful'})
    else:
        return JsonResponse({'error': 'Invalid credentials'}, status=401)
