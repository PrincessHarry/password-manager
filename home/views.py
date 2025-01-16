from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.cache import cache_control

from home.encrypt_util import encrypt, decrypt
from home.forms import RegistrationForm, LoginForm, UpdatePasswordForm
from home.models import UserPassword
from home.utils import generate_random_password
from django.db import transaction
from webauthn import generate_registration_options, generate_authentication_options, verify_registration_response, verify_authentication_response
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential
# from webauthn.helpers import (
#     verify_registration_response,
#     verify_authentication_response
# )




# home page
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def home_page(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    return render(request, 'pages/home.html')


# # user login
# class UserLoginView(LoginView):
#     form_class = LoginForm
#     template_name = 'pages/index.html'


# def user_login_view(request):
#     if request.user.is_authenticated:
#         return redirect('/home')
#     return UserLoginView.as_view()(request)

def user_login_view(request):
    if request.user.is_authenticated:
        return redirect('/home')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            if user:
                login(request, user)
                # Generate WebAuthn challenge for MFA
                return redirect('/home/authenticate/')  # Redirect to fingerprint verification
            else:
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()

    return render(request, 'pages/index.html', {'form': form})


# register new user
def register_page(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Account registered successfully. Please log in to your account.")
            login(request, user)
        else:
            print("Registration failed!")
    else:
        form = RegistrationForm()

    context = {'form': form}
    return render(request, 'pages/register.html', context)


# logout
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout_view(request):
    if not request.user.is_authenticated:
        return redirect('/')
    logout(request)
    return redirect('/')


# add new password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)

def add_new_password(request):
   
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    if request.method == 'POST':
        try:
           with transaction.atomic():
            username = request.POST['username']
            password = encrypt(request.POST['password'])
            application_type = request.POST['application_type']
            if application_type == 'Website':
                website_name = request.POST['website_name']
                website_url = request.POST['website_url']
                UserPassword.objects.create(username=username, password=password, application_type=application_type,
                                            website_name=website_name, website_url=website_url, user=request.user)
                messages.success(request, f"New password added for {website_name}")
            elif application_type == 'Desktop application':
                application_name = request.POST['application_name']
                UserPassword.objects.create(username=username, password=password, application_type=application_type,
                                            application_name=application_name, user=request.user)
                messages.success(request, f"New password added for {application_name}.")
            elif application_type == 'Game':
                game_name = request.POST['game_name']
                game_developer = request.POST['game_developer']
                UserPassword.objects.create(username=username, password=password, application_type=application_type,
                                            game_name=game_name, game_developer=game_developer, user=request.user)
                messages.success(request, f"New password added for {game_name}.")
            return HttpResponseRedirect("/add-password")
        except Exception as e:
            print(f"Database error: {e}")
            messages.error(request, f"Failed to save password: {str(e)}")
          


    return render(request, 'pages/add-password.html')


# edit password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def edit_password(request, pk):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    user_password = UserPassword.objects.get(id=pk)
    user_password.password = decrypt(user_password.password)
    form = UpdatePasswordForm(instance=user_password)

    if request.method == 'POST':
        if 'delete' in request.POST:
            # delete password
            user_password.delete()
            return redirect('/manage-passwords')
        form = UpdatePasswordForm(request.POST, instance=user_password)

        if form.is_valid():
            try:
                user_password.password = encrypt(user_password.password)
                form.save()
                messages.success(request, "Password updated.")
                user_password.password = decrypt(user_password.password)
                return HttpResponseRedirect(request.path)
            except ValidationError as e:
                form.add_error(None, e)

    context = {'form': form}
    return render(request, 'pages/edit-password.html', context)


# search password
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def search(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    logged_in_user = request.user
    logged_in_user_pws = UserPassword.objects.filter(user=logged_in_user)
    if request.method == "POST":
        searched = request.POST.get("password_search", "")
        users_pws = logged_in_user_pws.values()
        if users_pws.filter(Q(website_name=searched) | Q(application_name=searched) | Q(game_name=searched)):
            user_pw = UserPassword.objects.filter(
                Q(website_name=searched) | Q(application_name=searched) | Q(game_name=searched)).values()
            return render(request, "pages/search.html", {'passwords': user_pw})
        else:
            messages.error(request, "---YOUR SEARCH RESULT DOESN'T EXIST---")

    return render(request, "pages/search.html", {'pws': logged_in_user_pws})


# all passwords
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def manage_passwords(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    sort_order = 'asc'
    logged_in_user = request.user
    user_passwords = UserPassword.objects.filter(user=logged_in_user)
    if request.GET.get('sort_order'):
        sort_order = request.GET.get('sort_order', 'desc')
        user_passwords = user_passwords.order_by('-date_created' if sort_order == 'desc' else 'date_created')
    if not user_passwords:
        return render(request, 'pages/manage-passwords.html',
                      {'no_password': "No password available. Please add password."})
    return render(request, 'pages/manage-passwords.html', {'all_passwords': user_passwords, 'sort_order': sort_order})


# generate random password
def generate_password(request):
    password = generate_random_password()
    return JsonResponse({'password': password})



# Registration View
def register(request):
    # Generate registration options for the user
    options = generate_registration_options(
        rp_name="Password Manager",
        rp_id="password-manager-es06.onrender.com",  # Your domain
        user_name=request.user.username,
        user_id=str(request.user.id),
    )
    # Send options to the frontend
    request.session['webauthn_challenge'] = options.challenge
    return JsonResponse(options.dict())

# Registration Response (Frontend sends data here after user registers)
def complete_registration(request):
    # Parse registration credential and verify it
    credential = RegistrationCredential.parse_raw(request.body)
    challenge = request.session.get('webauthn_challenge')

    # Verify the registration response
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id="password-manager-es06.onrender.com",  # Your domain name
        expected_origin="https://password-manager-es06.onrender.com",
    )
    if verification.verified:
        # Store credential ID and public key
        request.user.webauthn_credential_id = verification.credential_id
        request.user.webauthn_public_key = verification.credential_public_key
        request.user.save()
        return JsonResponse({"status": "success"})

    return JsonResponse({"status": "failed"}, status=400)
# Authentication View (for fingerprint verification)
def authenticate(request):
    # Generate authentication options for the user
    options = generate_authentication_options(
        rp_id="password-manager-es06.onrender.com",
        user_verification="required",
        allow_credentials=[
            {
                "id": request.user.webauthn_credential_id,
                "type": "public-key",
            }
        ],
    )
    # Store the challenge in the session
    request.session['webauthn_challenge'] = options.challenge
    return JsonResponse(options.dict())
# Authentication Response (Frontend sends data here after authentication)
# def complete_authentication(request):
#       # Parse authentication credential sent by the client
#     credential = AuthenticationCredential.parse_raw(request.body)
#     challenge = request.session.get('webauthn_challenge')

#     # Verify the authentication response
#     verification =  verify_authentication_response(
#         credential=credential,
#         expected_challenge=challenge,
#         expected_rp_id="password-manager-uf04.onrender.com",
#         expected_origin="https://password-manager-uf04.onrender.com",
#         credential_public_key=request.user.webauthn_public_key,
#     )

#     if verification.verified:
#         return JsonResponse({"status": "authenticated"})
#     return JsonResponse({"status": "failed"}, status=400)

def complete_authentication(request):
    credential = AuthenticationCredential.parse_raw(request.body)
    challenge = request.session.get('webauthn_challenge')

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id="password-manager-es06.onrender.com",
        expected_origin="https://password-manager-es06.onrender.com",
        credential_public_key=request.user.webauthn_public_key,
    )

    if verification.verified:
        request.session['is_fingerprint_verified'] = True  # Set flag for MFA success
        return JsonResponse({"status": "authenticated"})
    return JsonResponse({"status": "failed"}, status=400)


# def get_decrypted_passwords(request):
#     if request.user.is_authenticated:
#         # Fetch encrypted passwords from the database
#         encrypted_passwords = encrypt(request.user)

#         # Decrypt passwords
#         decrypted_passwords = [
#             decrypt(password, request.user.secret_key)
#             for password in encrypted_passwords
#         ]

#         return JsonResponse({"passwords": decrypted_passwords})
#     return JsonResponse({"error": "Unauthorized"}, status=401)
def get_decrypted_passwords(request):
    if request.user.is_authenticated and request.session.get('is_fingerprint_verified', False):
        encrypted_passwords = UserPassword.objects.filter(user=request.user)
        decrypted_passwords = [
            {
                "application_type": password.application_type,
                "username": password.username,
                "password": decrypt(password.password)
            }
            for password in encrypted_passwords
        ]
        return JsonResponse({"passwords": decrypted_passwords})
    return JsonResponse({"error": "Unauthorized or MFA required"}, status=401)
