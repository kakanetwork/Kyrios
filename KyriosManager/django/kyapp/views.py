# ==================================================================================================================


from .models import CustomUser, AnaliseAPK
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.contrib import messages
from .analysis import validar_apk, analisar_arquivo, calc_media
from django.utils import timezone
from .security import user_required, hash_token, confirmacao_email
from django.conf import settings
import requests
import os

# ==================================================================================================================


# obtendo a chave do site reCAPTCHA do settings
recaptcha_site_key = settings.RECAPTCHA_SITE_KEY

# Função para verificar o reCAPTCHA
def recaptcha_verificador(captcha):
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
        return True  
    else:
        return False 


# ==================================================================================================================


# esta é a função responsável por lidar com o login de usuários.
def signin(request):

    # Definindo método a ser tratado
    if request.method == "POST":

        # Obtendo o email, senha e captcha enviados através do método POST
        email = request.POST.get('email')
        password = request.POST.get('password')
        captcha = request.POST.get('g-recaptcha-response')

        # Buscando o usuário no banco de dados com base no email fornecido
        user = CustomUser.objects.filter(email=email).first()

        # Verificando o captcha
        if recaptcha_verificador(captcha) == False:
            messages.error(request, 'O reCAPTCHA não foi realizado corretamente, tente novamente.')
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

                # Redirecionando para a página inicial
                return redirect('home')
            else:
                # Caso o email não tenha sido confirmado, exibe uma mensagem de erro
                messages.error(request, 'Por favor, confirme seu email antes de realizar o login!')

                # Opção para reenviar o link de confirmação no email
                messages.error(request, mark_safe(f'<b><a href="/reenviar/?email={email}" class="link-error">Clique aqui</a><b> para reenviar o email de confirmação.'))

                return redirect('signin')
        else:
            # Caso as credenciais estejam incorretas, exibe uma mensagem de erro
            messages.error(request, 'A senha ou email informados estão incorretos!')
            return redirect('signin')
            
    # Realizo o logout forçado, para tentativas de login duplicado.
    logout(request)

    # Renderiza a página de login se não for uma requisição POST
    return render(request, 'signin.html', {'recaptcha_site_key': recaptcha_site_key})


# ==================================================================================================================


# Esta função é responsável por lidar com o cadastro de novos usuários.
def signup(request):

    # Verifica se a requisição é do tipo POST, ou seja, se o formulário foi submetido.
    if request.method == "POST":

        # Obtém os dados do formulário de cadastro
        nome = request.POST.get("nome")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confpassword = request.POST.get("confpassword")
        
        # Verifica se a senha atende aos critérios de segurança
        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, '\n '.join(e.messages))
            return redirect('signup')

        # Verifica se as senhas fornecidas coincidem
        if password != confpassword:
            messages.error(request, 'As senhas não conferem!')
            return redirect('signup')
        
        # Verifica se o email já está cadastrado no sistema
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'O email informado já está cadastrado!')
            return redirect('signup')
        
        # Função que realiza o envio e configuração do email de confirmação da conta
        if not confirmacao_email(email):
            messages.error(request, 'Ocorreu um erro ao tentar enviar o email de confirmação!')
            return redirect('signup')
        
        # Cria um novo usuário no sistema
        try:
            new_user = CustomUser.objects.create_user(email=email, username=email, first_name=nome, password=password)
        except Exception as erro:
            messages.error(request, f'Ocorreu um erro ao tentar criar o usuário! {erro}')
            return redirect('signup')
        
        # Exibe mensagem de sucesso após o cadastro
        messages.success(request, 'Seu usuário foi criado!')

        # Mensagem de ativação da conta
        messages.success(request, 'Enviamos um e-mail de ativação da conta, para você!')
        
        return redirect('signup')
    
    # Realizo o logout forçado, para tentativas de login duplicado.
    logout(request)

    # Renderiza a página de cadastro se não for uma requisição POST
    return render(request, 'signup.html')


# ==================================================================================================================


# Esta função realiza a ativação da conta.
def ativar_email(request):
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

        messages.success(request, 'Sua conta foi ativada com sucesso!')
        return redirect('signin')
    else:
        messages.error(request, 'Houve algum erro na ativação da sua conta!')
        return redirect('signin')


# ==================================================================================================================


# Esta função realiza o reenvio do link de confirmação
def reenvio_confirmacao(request):
    # Resgata o email da URL com método GET
    email = request.GET.get('email')

    # Inicializa a função de confirmação que envia de fato o email
    if not confirmacao_email(email):
        messages.error(request, 'Ocorreu um erro ao tentar enviar o email de confirmação!')
        return redirect('signin')
    
    # Se sucesso, retorna sua devida resposta
    messages.success(request, 'Email de confirmação reenviado com sucesso!')
    return redirect('signin')


# ==================================================================================================================


# Esta função realiza o logout do usuário.
def deslogar(request):
    # Realiza o logout do usuário
    logout(request)  
    # Redireciona para a página de login
    return redirect('signin')  


# ===================================================================================================================

# esta é a função principal da aplicação, responsável por lidar com a página inicial.

# BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Define o diretório base como o diretório atual do script
# ZIP_DIR = os.path.join(BASE_DIR, "arquivos_zip")  # Define um subdiretório para os arquivos ZIP


@user_required
def home(request):
    # Obtendo o ID do usuário da sessão
    user_id = request.session['user_id']
    
    # Verificando se o método da requisição é POST e se um arquivo APK foi enviado
    if request.method == 'POST' and request.FILES.get('apk_file'):
        flag_dinamica = request.POST.get('AD')  #  Flag se necessita de análise dinâmica
        # Obtendo o arquivo APK enviado
        apk_file = request.FILES['apk_file']
        nome_arquivo, extensao = os.path.splitext(apk_file.name)

        # Validando se o arquivo enviado é um APK
        if validar_apk(apk_file, extensao):
            # Exibindo mensagem de sucesso antes de iniciar a análise
            messages.success(request, 'A análise do APK está em andamento. Por favor, aguarde...')

            # Analisando o arquivo APK e exibindo mensagem de sucesso ou erro
            if analisar_arquivo(apk_file, user_id, nome_arquivo, extensao, flag_dinamica):
                messages.success(request, 'A análise do APK foi concluída com sucesso!')
            else:
                messages.error(request, 'Ocorreu um erro ao analisar o APK.')
        else:
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
    return render(request, 'home.html', {'analises_apk': analises_apk, 'media_tempo': media_tempo, 'total': total, 'total_semana': total_semana})


# ==================================================================================================================


# esta é a função responsável por lidar com a exibição da tabela de análises de APK.
@user_required
def table(request):
    user_id = request.session['user_id']
    analises_apk = AnaliseAPK.objects.filter(usuario=user_id).order_by('-id')
    return render(request, 'table.html', {'analises_apk': analises_apk})


# ==================================================================================================================


# esta é a função responsável por lidar com a exibição de detalhes de uma análise de APK específica.
@user_required
def detalhar_analise(request, id):
    user_id = request.session['user_id']
    analises_apk = AnaliseAPK.objects.filter(usuario=user_id, id_json=id)
    return render(request, 'table.html', {'analises_apk': analises_apk, 'flag': True})


# ==================================================================================================================


# esta é a função responsável por lidar com a exclusão de uma análise de APK.
@user_required
def deletar_analise(request, id, flag):
    user_id = request.session.get('user_id')

    if flag not in ["3K8J7D", "9G2F4L"]:
        return redirect('home')
    try:
        analise = AnaliseAPK.objects.get(usuario=user_id, id_json=id)
    except AnaliseAPK.DoesNotExist:
        return redirect('home')
   
    analise.delete()

    if flag == "3K8J7D":
        return redirect('home')
    elif flag == "9G2F4L":
        return redirect('table')


# ==================================================================================================================
