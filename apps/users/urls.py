from django.urls import path
from . import views
from .views import (
    ForgotPasswordView,
    ResetPasswordView,
    UpdatePasswordView,
    DisposerDashboardView,
    RecyclerDashboardView,
    UpdateUserView
)

app_name = 'users'

urlpatterns = [
    # User Authentication
    path('signup/', views.signup, name='signup'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),


    # Password Management
    path('forgotPassword/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('resetPassword/', ResetPasswordView.as_view(), name='reset_password'),
    path('updatePassword/', UpdatePasswordView.as_view(), name='update_password'),

    # User dashboard management
    path('disposer-dashboard/', DisposerDashboardView.as_view(), name='disposer-dashboard'),
    path('recycler-dashboard/', RecyclerDashboardView.as_view(), name='recycler-dashboard'),

    # Backward compatibility - old endpoint maps to disposer dashboard
    path('user-dashboard/', DisposerDashboardView.as_view(), name='user-dashboard'),

    path('update-user/', UpdateUserView.as_view(), name='update-user'),

]
