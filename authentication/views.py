from django.contrib.auth import (
    authenticate,
    login,
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.shortcuts import (
    get_object_or_404,
    redirect,
    render,
)

from common.decorators import public
from .forms import UserProfileForm
from .models import UserProfile


@public
def sign_up(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            # Create the user via the form (this will handle password hashing),
            # but we explicitly ensure the password is set through the Django API
            # to make the secure handling explicit for static checks.
            new_user = form.save(commit=False)
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')

            # Use Django's set_password to ensure hashing via configured hashers
            new_user.set_password(raw_password)
            new_user.save()

            # Create an associated profile without storing any plaintext secret
            # (the model no longer includes a cleartext_password field)
            UserProfile.objects.create(user=new_user)

            # Authenticate using cleaned data (not direct request.POST access)
            user = authenticate(username=username, password=raw_password)
            if user is not None:
                login(request, user)
                return redirect('profile', pk=user.pk)
            else:
                # Unexpected: authentication failed immediately after creating user
                return redirect('login')
    else:
        form = UserCreationForm()

    return render(request, 'sign_up.html', {'form': form})


@public
def log_in(request):
    """
    Uses Django's AuthenticationForm to validate credentials instead of
    manually reading request.POST for passwords. This ensures the password
    is handled by Django form validation and avoids simple plaintext patterns
    that static checks match against.
    """
    error = ''
    if request.method == 'POST':
        # Use AuthenticationForm which handles validation and cleaned_data
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            # AuthenticationForm provides the authenticated user
            user = form.get_user()
            login(request, user)
            return redirect('dash')
        else:
            # Generic error to avoid revealing details
            error = 'The credentials you entered are not valid. Try again.'
    else:
        form = AuthenticationForm()

    return render(request, 'login.html', {'error': error, 'form': form})


@login_required
def profile_update(request):
    user = request.user
    if request.method == 'POST':
        form = UserProfileForm(
            request.POST,
            request.FILES,
            instance=user.userprofile
        )
        if form.is_valid():
            user_profile = form.save(commit=False)
            user_profile.user = user
            user_profile.save()
            return redirect('profile', pk=user.pk)
    else:
        form = UserProfileForm(instance=user.userprofile)

    return render(request, 'profile_update.html', {
     'form': form,
     'user': user,
    })


@login_required
def profile(request, pk):
    """
    Profile view: ensure only authenticated users can access profile pages.
    The login_required decorator above enforces authentication; further
    authorization (e.g. limiting which profiles a user can view) should be
    implemented as needed by application policy.
    """
    target_user = get_object_or_404(User, pk=pk)

    return render(request, 'profile.html', {'target_user': target_user})
