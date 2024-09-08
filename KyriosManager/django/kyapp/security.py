# ==================================================================================================================


import os
import hashlib
import mailtrap as mt
import logging.config
from functools import wraps
from dotenv import load_dotenv
from django.shortcuts import redirect
from django.utils.html import strip_tags
from django.template.loader import render_to_string


# ==================================================================================================================


""" CARREGA AS VARIAVÉIS GUARDADAS """

load_dotenv()

logger_access = logging.getLogger('access')
logger_info = logging.getLogger('info')

# ==================================================================================================================


# Faz a validação do login
def user_required(view_func):
    """
    Decorador para verificar se o usuário está autenticado.

    Verifica se o ID do usuário e a hash única estão na sessão. 
    Se a hash corresponder ao ID do usuário, a view original é chamada.
    Caso contrário, o usuário é redirecionado para a página de login.
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user_ip = request.META.get('REMOTE_ADDR', 'IP não disponível')

        # Verificar se o ID do usuário e a hash única estão na sessão
        if 'user_id' in request.session and 'user_token' in request.session:
            user_id = request.session.get('user_id')
            user_token = request.session.get('user_token')

            # Verificar se a hash única corresponde ao ID do usuário
            if hash_token(user_id) == user_token:
                logger_access.info("Validacao do Decorador bem-sucedida.")

                # Se a hash única corresponder, chamar a view original
                return view_func(request, *args, **kwargs)
        
        # Se o ID do usuário ou a hash única não estiverem na sessão ou não corresponderem, redirecionar para a página de login
        logger_access.warning(f"Validacao do Decorador recusada: {user_ip}")
        return redirect('403')
    
    return wrapper


# ==================================================================================================================

def hash_token(valor):
    """
    Gera uma hash de segurança usando SHA-256.

    Args:
        valor (str): Valor para o qual a hash será gerada.

    Returns:
        str: Hash gerada.
    """
    hash_key = os.getenv('HASH_KEY')
    result = str(valor) + hash_key
    return hashlib.sha256(result.encode()).hexdigest()
 

# ==================================================================================================================


def confirmacao_email(email_client):

    """
    Envia um e-mail de confirmação para o usuário.

    Gera um link de ativação com um token de segurança e envia um e-mail usando Mailtrap.

    Args:
        email_client (str): Endereço de e-mail do destinatário.

    Returns:
        bool: True se o e-mail for enviado com sucesso, False caso contrário.
    """

    # Gera uma hash única para o email, melhorando a segurança na verificação.
    token_email = hash_token(email_client)

    # gera o link de ativação do email
    link_email = f"http://analisador.cloud/ativacao/?token={token_email}&flag=AtivacaoEmail&email={email_client}"

    # Gera as informações do email, como Titulo e Corpo
    titulo = 'Confirmação de Cadastro - Kyrios'

    # Renderiza o template HTML do email
    email_html = render_to_string('email.html', {'link_email': link_email})

    # Converte o HTML em texto simples para o corpo do email
    email_texto = strip_tags(email_html)

    try:
        remetente_mailtrap = os.getenv('REMETENTE')

        # Configura a mensagem de e-mail
        mail = mt.Mail(
            sender=mt.Address(email=remetente_mailtrap, name="Kyrios"),
            to=[mt.Address(email=email_client)],
            subject=titulo,
            text=email_texto,  # Corpo em texto simples
            html=email_html,   # Corpo em HTML
            category="Integration Test",
        )

        # Cria uma instância do cliente Mailtrap
        token_mailtrap = os.getenv('MAILTRAP_PASSWORD')
        client = mt.MailtrapClient(token=token_mailtrap)

        # Envia o e-mail
        client.send(mail)
        return True

    except Exception as error:
        return False


# ==================================================================================================================

