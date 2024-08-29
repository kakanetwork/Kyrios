# ==================================================================================================================


from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.contrib import messages
from django.utils import timezone
from django.conf import settings
import requests
import os

# ==================================================================================================================


# esta é a função responsável por lidar com o login de usuários.
def signin(request):

    # Definindo método a ser tratado
    if request.method == "POST":

        # Redirecionando para a página inicial
        return redirect('home')

    # Renderiza a página de login se não for uma requisição POST
    return render(request, 'signin.html')


# ==================================================================================================================


# esta é a função principal da aplicação, responsável por lidar com a página inicial.
def home(request):

    # Renderizando o template 'home.html' 
    return render(request, 'home.html')


# ==================================================================================================================