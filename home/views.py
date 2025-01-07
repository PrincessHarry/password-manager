from django.contrib import messages
from django.contrib.auth import logout
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
from webauthn import generate_registration_options, generate_authentication_options
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential
from webauthn.helpers import (
    verify_registration_response,
    verify_authentication_response
)




# home page
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def home_page(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % ('/', request.path))
    return render(request, 'pages/home.html')


# user login
class UserLoginView(LoginView):
    form_class = LoginForm
    template_name = 'pages/index.html'


def user_login_view(request):
    if request.user.is_authenticated:
        return redirect('/home')
    return UserLoginView.as_view()(request)


# register new user
def register_page(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
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
        rp_id="password-manager-uf04.onrender.com",  # Your domain
        user_name=request.user.username,
        user_id=request.user.id,
    )
    # Send options to the frontend
    return JsonResponse(options)

# Registration Response (Frontend sends data here after user registers)
def complete_registration(request):
    # Parse registration credential and verify it
    registration_credential = RegistrationCredential.parse_raw(request.body)
    verified = verify_registration_response(
        registration_credential,
        expected_rp_id="password-manager-uf04.onrender.com",
        expected_user=request.user
    )
    if verified:
        return JsonResponse({"status": "success"})
    else:
        return JsonResponse({"status": "failed"}, status=400)

# Authentication View (for fingerprint verification)
def authenticate(request):
    # Generate authentication options for the user
    options = generate_authentication_options(
        rp_id="password-manager-uf04.onrender.com",
        user_id=request.user.id,
    )
    return JsonResponse(options)

# Authentication Response (Frontend sends data here after authentication)
def complete_authentication(request):
    # Parse authentication credential and verify it
    authentication_credential = AuthenticationCredential.parse_raw(request.body)
    verified = verify_authentication_response(
        authentication_credential,
        expected_rp_id="password-manager-uf04.onrender.com",
        expected_user=request.user
    )
    if verified:
        return JsonResponse({"status": "authenticated"})
    else:
        return JsonResponse({"status": "failed"}, status=400)
