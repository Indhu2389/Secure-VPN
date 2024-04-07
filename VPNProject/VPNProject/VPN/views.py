from django.http import HttpResponse,HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.urls import reverse
import requests
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
import uuid
from .models import LoginUser
from .models import CustomUser
import subprocess
from subprocess import TimeoutExpired  
import threading
import socket

def login_page(request):
    return render(request, 'login.html')

def vpn_connection_success(request):
    if request.method == 'POST':
        # If the user clicked the slider button to disconnect VPN
        if 'disconnect' in request.POST:
            # Perform any necessary actions to disconnect VPN
            # For now, let's redirect the user to the login page
            return redirect('login_page')
    # Render the VPN connection success template
    return render(request, 'vpn_success.html')

def connect_to_vpn():
    try:
        vpn_command = "sudo python3 /home/seed/Desktop/VPNProject/VPNProject/utills/vpn_client.py"
        result = subprocess.run(vpn_command, shell=True, check=True)
        print(result.returncode)
        print("VPN connection established successfully.")
        return True  # Return True if the client code runs successfully
        #return HttpResponse("Connection successful")
    except ConnectionRefusedError:
        # Handle the connection refused error
        error_message = "Connection refused: The server refused the connection"
        # Log the error or perform other actions as needed
        print(error_message)
        return HttpResponse(error_message)
    except Exception as e:
        print("Error occurred while connecting to VPN:", e)
        return False  # Return False if there's an error
    except subprocess.CalledProcessError as e:
        print("Error occurred while connecting to VPN:", e)
        return False  # Return False if there's an error

def login(request):
    if request.method == 'POST':
        email = request.POST.get('username')
        password = request.POST.get('password')
        try:
            user = LoginUser.objects.get(email=email, password=password)
            #messages.success(request, 'Login successful. VPN connection in progress...')
            sock = socket.create_connection(('10.9.0.11', 5555))
            sock.close()  # Close the connection
            vpn_thread = threading.Thread(target=connect_to_vpn)
            vpn_thread.start()
            if vpn_thread:
                # VPN connection succeeded
               # messages.success(request, 'VPN connection succeeded.')
                return redirect('vpn_connection_success') #HttpResponse("Login successful. VPN connection succeeded. Please proceed with ping.")
            else:
                # VPN connection failed
                #messages.error(request, 'VPN connection failed.')
                return HttpResponse("Login successful. VPN connection failed.")
        except LoginUser.DoesNotExist:
            messages.error(request, 'Invalid credentials. Please try again.')
            return redirect('login_page')
        except ConnectionRefusedError:
        # Handle the connection refused error
            error_message = "Unable to establish a connection: The server is currently unreachable or unavailable. Please try again later."
            return HttpResponse(error_message)
        # Log the error or perform other actions as needed
        except socket.timeout:
            print("Connection timed out: The connection attempt took too long to complete.")
            #print(error_message)
            return HttpResponse(error_message)
    else:
        return HttpResponse("Invalid request method.")

def register(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')

        if password != password_confirm:
            messages.error(request, 'Passwords do not match.')
            return redirect('register')

        user = CustomUser.objects.create_user(email=email, password=password)
        user.save()
        login_user = LoginUser(email=email, password=password)
        login_user.save()
        messages.success(request, 'Registration successful. You can now log in.')
        return redirect('login_page')
    else:
        return render(request, 'registration.html')


def forget_password(request):
    return render(request, 'forget_password.html')


def send_reset_link(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'User with this email does not exist.')
            return redirect('forget_password')

        token = str(uuid.uuid4())
        user.password_reset_token = token
        user.save()

        reset_link = f"{request.scheme}://{request.get_host()}/reset-password/{token}"
        send_mail(
            'Password Reset Link',
            f'Click the following link to reset your password: {reset_link}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        messages.success(request, 'Password reset link sent to your email.')
        return redirect('login_page')
    else:
        return redirect('forget_password')


def reset_password(request, token):
    if request.method == 'POST':
        try:
            user = CustomUser.objects.get(password_reset_token=token)
        except CustomUser.DoesNotExist:
            messages.error(request, 'Invalid password reset link.')
            return redirect('login_page')

        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')

        if password != password_confirm:
            messages.error(request, 'Passwords do not match.')
            return redirect('reset_password', token=token)

        user.set_password(password)
        user.password_reset_token = None
        user.save()
        messages.success(request, 'Password reset successfully.')
        return redirect('login_page')
    else:
        context = {
            'token': token,
        }
        # Handle GET request separately
        # You may want to render a form for resetting the password
        return render(request, 'reset_password.html', context)



def ping_host(request):
    host_url = 'http://10.9.0.11:5555/ping'  # Replace 'host_ip' with the actual IP of your host

    try:
        response = requests.get(host_url)
        if response.status_code == 200:
            return HttpResponse('Host is reachable!')
        else:
            return HttpResponse('Host is not reachable!')
    except requests.ConnectionError:
        return HttpResponse('Failed to connect to host.')
