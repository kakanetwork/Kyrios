# ==================================================================================================================

import os
import requests
import logging.config
from django.conf import settings
from django.utils import timezone
from django.contrib import messages
from .models import CustomUser, AnaliseAPK
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.http import FileResponse
from django.utils.safestring import mark_safe
from .analysis.analysis import analisar_arquivo
from django.core.exceptions import ValidationError
from .analysis.utils import validar_apk, calc_media
from .security import user_required, hash_token, confirmacao_email
from django.contrib.auth.password_validation import validate_password


# ==================================================================================================================


logger_access = logging.getLogger('access')
logger_error = logging.getLogger('error')
logger_info = logging.getLogger('info')


# ==================================================================================================================


# obtendo a chave do site reCAPTCHA do settings
recaptcha_site_key = settings.RECAPTCHA_SITE_KEY

# Função para verificar o reCAPTCHA
def recaptcha_verificador(captcha):
    """
    Verifica o reCAPTCHA enviando uma solicitação para o Google reCAPTCHA API.

    Args:
        captcha (str): O token do reCAPTCHA enviado pelo cliente.

    Returns:
        bool: Retorna True se o reCAPTCHA for verificado com sucesso, False caso contrário.
    """

    secret_key = settings.RECAPTCHA_SECRET_KEY
    
    # Fazendo uma solicitação POST para o Google reCAPTCHA API para verificar o reCAPTCHA
    dados = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret': secret_key,
            'response': captcha
        }
    )
    
    # Converta os dados de resposta em formato JSON
    result = dados.json()
    
    # Verificando se a resposta foi bem-sucedida ou não
    if result['success']:
        logger_info.info("Recaptcha Verificado.")
        return True  
    else:
        logger_info.info("Recaptcha Invalido.")
        return False 


# ==================================================================================================================


# esta é a função responsável por lidar com o login de usuários.
def signin(request):
    """
    Lida com o processo de login do usuário, incluindo verificação de captcha e autenticação.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP que contém os dados do login.

    Returns:
        HttpResponseRedirect: Redireciona para a página inicial em caso de sucesso, ou de volta para a página de login em caso de falha.
    """

    user_ip = request.META.get('REMOTE_ADDR', 'IP não disponível')
    user_agent = request.META.get('HTTP_USER_AGENT', 'User-Agent não disponível')

    # Definindo método a ser tratado
    if request.method == "POST":

        # Obtendo o email, senha e captcha enviados através do método POST
        email = request.POST.get('email')
        password = request.POST.get('password')
        captcha = request.POST.get('g-recaptcha-response')

        logger_access.info(f"Pedido de Autenticacao: {email} - IP: {user_ip} - Agent: {user_agent}")

        # Buscando o usuário no banco de dados com base no email fornecido
        user = CustomUser.objects.filter(email=email).first()

        # Verificando o captcha
        if recaptcha_verificador(captcha) == False:
            messages.error(request, 'O reCAPTCHA nao foi realizado corretamente, tente novamente.')
            return redirect('signin')
        
        # Verificando se o usuário existe e se a senha está correta
        if user is not None and user.check_password(password):
            if user.email_confirmed:
                # Armazenando o nome de usuário, ID e Hash de Autenticação na Sessão
                request.session['username'] = user.first_name
                request.session['user_id'] = user.id
                request.session['user_token'] = hash_token(user.id)
                
                # Autenticando o usuário no sistema
                login(request, user)

                logger_access.info(f"Login Realizado: {email} - IP: {user_ip} - Agent: {user_agent}")

                # Redirecionando para a página inicial
                return redirect('home')
            else:
                # Caso o email não tenha sido confirmado, exibe uma mensagem de erro
                messages.error(request, 'Por favor, confirme seu email antes de realizar o login!')

                # Opção para reenviar o link de confirmação no email
                messages.error(request, mark_safe(f'<b><a href="/reenviar/?email={email}" class="link-error">Clique aqui</a><b> para reenviar o email de confirmação.'))

                logger_access.info(f"Email de Confirmação Enviado: {email} - IP: {user_ip} - Agent: {user_agent}")

                return redirect('signin')
        else:
            logger_access.info(f"Login Incorreto: {email} - IP: {user_ip} - Agent: {user_agent}")
            # Caso as credenciais estejam incorretas, exibe uma mensagem de erro
            messages.error(request, 'A senha ou email informados estão incorretos!')
            return redirect('signin')
            
    # Realizo o logout forçado, para tentativas de login duplicado.
    logout(request)

    logger_access.info(f"Acesso - IP: {user_ip} - Agent: {user_agent}")

    # Renderiza a página de login se não for uma requisição POST
    return render(request, 'signin.html', {'recaptcha_site_key': recaptcha_site_key})


# ==================================================================================================================


# Esta função é responsável por lidar com o cadastro de novos usuários.
def signup(request):
    """
    Lida com o processo de cadastro de novos usuários, incluindo validação de senha, verificação de e-mail, e envio de e-mail de confirmação.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP que contém os dados do formulário de cadastro.

    Returns:
        HttpResponseRedirect: Redireciona para a página de cadastro em caso de erro ou após a criação bem-sucedida do usuário.
    """

    user_ip = request.META.get('REMOTE_ADDR', 'IP não disponível')
    user_agent = request.META.get('HTTP_USER_AGENT', 'User-Agent não disponível')

    # Verifica se a requisição é do tipo POST, ou seja, se o formulário foi submetido.

    if request.method == "POST":

        # Obtém os dados do formulário de cadastro
        nome = request.POST.get("nome")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confpassword = request.POST.get("confpassword")
        
        logger_access.info(f"Pedido de Criação de Conta: {email} - IP: {user_ip} - Agent: {user_agent}")

        # Verifica se a senha atende aos critérios de segurança
        try:
            validate_password(password)
        except ValidationError as e:
            logger_info.info("Senha não é forte suficiente.")
            messages.error(request, '\n '.join(e.messages))
            return redirect('signup')

        # Verifica se as senhas fornecidas coincidem
        if password != confpassword:
            logger_info.info("Senhas não condizem.")
            messages.error(request, 'As senhas não conferem!')
            return redirect('signup')
        
        if CustomUser.objects.filter(email=email).exists():
            logger_info.warning(f"Tentativa de cadastro com e-mail: {email}")
            messages.error(request, 'Não foi possível criar a conta. Verifique os dados e tente novamente.')
            return redirect('signup')
        
        # Função que realiza o envio e configuração do email de confirmação da conta
        if not confirmacao_email(email):
            logger_error.error(f"Email de Confirmação não enviado: {email}")
            messages.error(request, 'Ocorreu um erro ao tentar enviar o email de confirmação!')
            return redirect('signup')
        
        # Cria um novo usuário no sistema
        try:
            new_user = CustomUser.objects.create_user(email=email, username=email, first_name=nome, password=password)
        except Exception as erro:
            logger_error.error(f"Usuario não criado: {erro}")
            messages.error(request, f'Ocorreu um erro ao tentar criar o usuário! {erro}')
            return redirect('signup')
        
        # Exibe mensagem de sucesso após o cadastro
        messages.success(request, 'Seu usuário foi criado!')

        # Mensagem de ativação da conta
        messages.success(request, 'Enviamos um e-mail de ativação da conta, para você!')
        logger_info.info("Usuario criado e Email enviado.")

        return redirect('signup')
    
    # Realizo o logout forçado, para tentativas de login duplicado.
    logout(request)

    # Renderiza a página de cadastro se não for uma requisição POST
    return render(request, 'signup.html')


# ==================================================================================================================


# Esta função realiza a ativação da conta.
def ativar_email(request):
    """
    Realiza a ativação da conta do usuário com base no email e token fornecidos na URL.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP que contém os parâmetros de email, token e flag.

    Returns:
        HttpResponseRedirect: Redireciona para a página de login após a ativação ou em caso de erro.
    """

    # Resgata as variáveis do link
    email = request.GET.get('email')
    token = request.GET.get('token')
    flag = request.GET.get('flag')

    # Consulta se o email existe no BD / Se ele ainda não foi confirmado
    user = CustomUser.objects.filter(email=email, email_confirmed=False).first()

    # Verificar se a hash única corresponde e se de fato existe o usuário no BD e a Flag existe
    if hash_token(email) == token and user is not None and flag:

        # Se tudo ok, ele é ativado com sucesso e salvo no BD
        user.email_confirmed = True
        user.save()

        logger_info.info(f"Conta Ativada com Sucesso: {email}")
        messages.success(request, 'Sua conta foi ativada com sucesso!')
        return redirect('signin')
    else:
        logger_error.error(f"Não foi possível ativar a conta: {email}")
        messages.error(request, 'Houve algum erro na ativação da sua conta!')
        return redirect('signin')


# ==================================================================================================================


# Esta função realiza o reenvio do link de confirmação
def reenvio_confirmacao(request):
    """
    Reenvia o link de confirmação de conta para o email fornecido na URL.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP que contém o parâmetro de email.

    Returns:
        HttpResponseRedirect: Redireciona para a página de login após o reenvio do email ou em caso de erro.
    """

    # Resgata o email da URL com método GET
    email = request.GET.get('email')

    # Inicializa a função de confirmação que envia de fato o email
    if not confirmacao_email(email):
        logger_error.critical(f"Não foi reenviar o email de confirmação: {email}")
        messages.error(request, 'Ocorreu um erro ao tentar enviar o email de confirmação!')
        return redirect('signin')
    
    # Se sucesso, retorna sua devida resposta
    logger_info.info(f"Reenvio realizado: {email}")
    messages.success(request, 'Email de confirmação reenviado com sucesso!')
    return redirect('signin')


# ==================================================================================================================


# Esta função realiza o logout do usuário.
def deslogar(request):
    """
    Realiza o logout do usuário e redireciona para a página de login.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP que contém as informações do usuário.

    Returns:
        HttpResponseRedirect: Redireciona para a página de login após o logout.
    """

    user_ip = request.META.get('REMOTE_ADDR', 'IP não disponível')
    logger_access.info(f"Usuario deslogado: {user_ip}")
    # Realiza o logout do usuário
    logout(request)  
    # Redireciona para a página de login
    return redirect('signin')  


# ===================================================================================================================


# esta é a função principal da aplicação, responsável por lidar com a página inicial.
@user_required
def home(request):
    """
    Lida com a página inicial da aplicação, permite o upload de arquivos APK, 
    exibe análises de APK anteriores e estatísticas de uso.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP contendo a sessão do usuário e os dados do formulário.

    Returns:
        HttpResponse: A página renderizada contendo os dados de análises de APK e estatísticas para o usuário.
    """

    # Obtendo o ID do usuário da sessão
    user_id = request.session['user_id']

    # Verificando se o método da requisição é POST e se um arquivo APK foi enviado
    if request.method == 'POST' and request.FILES.get('apk_file'):

        flag_dinamica = request.POST.get('AD')  #  Flag se necessita de análise dinâmica
        # Obtendo o arquivo APK enviado
        apk_file = request.FILES['apk_file']
        nome_arquivo, extensao = os.path.splitext(apk_file.name)

        logger_info.info(f"Submissao de Arquivo: {flag_dinamica}")

        # Validando se o arquivo enviado é um APK
        if validar_apk(apk_file, extensao):
            # Exibindo mensagem de sucesso antes de iniciar a análise
            messages.success(request, 'Por favor, contribua para o meu Humilde Café XD. <a href="https://ko-fi.com/kyriosanalysis" target="_blank" class="doacao-link">Faça uma doação aqui!</a>.')

            logger_info.info("APK Validado.")

            # Analisando o arquivo APK e exibindo mensagem de sucesso ou erro
            flag, msg, info_msg = analisar_arquivo(apk_file, user_id, nome_arquivo, extensao, flag_dinamica)

            if not flag:
                messages.error(request, msg)
            else:
                messages.success(request, msg)

            # Exibindo a mensagem informativa, se houver
            if info_msg:
                messages.warning(request, info_msg)

        else:
            logger_info.info(f"APK não validado.")
            # Exibindo mensagem de erro se o arquivo enviado não for um APK válido
            messages.error(request, 'O arquivo enviado não é um APK válido.')
            
        # Redirecionando de volta para a página inicial após o processamento do formulário
        return redirect('home')
    
    # Obtendo todas as análises de APK associadas ao usuário atual e ordenando por ID em ordem decrescente
    analises_apk = AnaliseAPK.objects.filter(usuario=user_id).order_by('-id')

    # Calculando a média de tempo para escanear todos os APKs
    media_tempo = calc_media(analises_apk)

    # Obtendo a contagem total de análises de APK
    total = analises_apk.count()

    # Obtendo a contagem de análises de APK da última semana
    semana_passada = timezone.now() - timezone.timedelta(days=7)
    total_semana = analises_apk.filter(data__gte=semana_passada).count()
    
    analises_apk = analises_apk[:10]

    # Renderizando o template 'home.html' com os dados necessários
    return render(request, 'home.html', {
        'analises_apk': analises_apk, 
        'media_tempo': media_tempo, 
        'total': total, 
        'total_semana': total_semana,
    })


# ==================================================================================================================


# esta é a função responsável por lidar com a exibição da tabela de análises de APK.
@user_required
def table(request):
    """
    Exibe a tabela com as análises de APK realizadas pelo usuário.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP contendo a sessão do usuário.

    Returns:
        HttpResponse: A página renderizada contendo a tabela de análises de APK.
    """
    user_id = request.session['user_id']
    analises_apk = AnaliseAPK.objects.filter(usuario=user_id).order_by('-id')

    primeiro_upload_url = None
    primeiro_analise = analises_apk[0] if analises_apk else None

    # Verifica se primeiro_analise existe e se "upload_url" é uma chave dentro do dicionário "dinamica"
    if primeiro_analise and 'upload_url' in primeiro_analise.dinamica:
        primeiro_upload_url = primeiro_analise.dinamica['upload_url']

    return render(request, 'table.html', {'analises_apk': analises_apk, 'upload_url': primeiro_upload_url})


# ==================================================================================================================


# esta é a função responsável por lidar com a exibição de detalhes de uma análise de APK específica.
@user_required
def detalhar_analise(request, id):
    """
    Exibe os detalhes de uma análise de APK específica realizada pelo usuário.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP contendo a sessão do usuário.
        id (int): O ID da análise a ser detalhada.

    Returns:
        HttpResponse: A página renderizada contendo os detalhes da análise de APK.
    """
    user_id = request.session['user_id']
    logger_info.info(f"Analise Detalhada: {user_id}/{id}")
    analises_apk = AnaliseAPK.objects.filter(usuario=user_id, id_json=id)
    return render(request, 'table.html', {'analises_apk': analises_apk, 'flag': True})


# ==================================================================================================================


# esta é a função responsável por lidar com a exclusão de uma análise de APK.
@user_required
def deletar_analise(request, id, flag):
    """
    Exclui uma análise de APK realizada pelo usuário, verificando a flag de segurança.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP contendo a sessão do usuário.
        id (int): O ID da análise a ser excluída.
        flag (str): Flag de segurança necessária para a exclusão.

    Returns:
        HttpResponseRedirect: Redireciona para a página inicial ou para a tabela de análises, dependendo da flag.
    """
    user_id = request.session.get('user_id')

    if flag not in ["3K8J7D", "9G2F4L"]:
        logger_info.warning(f"Flag de Exclusão Invalida: {flag}")
        return redirect('home')
    try:
        analise = AnaliseAPK.objects.get(usuario=user_id, id_json=id)
    except AnaliseAPK.DoesNotExist:
        logger_info.warning(f"APK não existente: {id}")
        return redirect('home')
   
    analise.delete()
    logger_info.info(f"APK deletado: {id}")

    if flag == "3K8J7D":
        return redirect('home')
    elif flag == "9G2F4L":
        return redirect('table')


# ==================================================================================================================


@user_required
def baixar_pcap(request, caminho_arquivo):
    """
    Realiza o download de um arquivo PCAP do servidor.

    Args:
        request (HttpRequest): O objeto de solicitação HTTP contendo a solicitação de download.
        caminho_arquivo (str): O caminho completo do arquivo PCAP no servidor.

    Returns:
        HttpResponse: A resposta de arquivo para o download ou redireciona para a tabela de análises se o arquivo não existir.
    """
    logger_info.info(f"Download: {caminho_arquivo}")
    if os.path.exists(caminho_arquivo):
        nome_arquivo = os.path.basename(caminho_arquivo)  # Extrai o nome do arquivo do caminho
        response = FileResponse(open(caminho_arquivo, 'rb'), as_attachment=True, filename=nome_arquivo)
        return response
    else:
        return redirect('table')
    

# ==================================================================================================================

def erro_403(request):
    return render(request, '403.html')

# ==================================================================================================================
