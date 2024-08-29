from .models import AnaliseAPK
import time
import requests
from dotenv import load_dotenv
import os

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()


# ==================================================================================================================


# Esta função é responsável por validar se o arquivo enviado é um APK válido.
def validar_apk(arquivo, extensao):
    """
    Valida se o arquivo enviado é um APK válido.

    Parâmetros:
        arquivo: Arquivo enviado que deve ser validado.
        extensao: Extensão do arquivo (espera-se que seja '.apk').

    Retorna:
        True se o arquivo for um APK válido, False caso contrário.
    """
    # Assinatura de um arquivo APK
    apk_signature = b'\x50\x4b\x03\x04'

    # Retorna ao início do arquivo
    arquivo.seek(0)

    # Lê os primeiros bytes do arquivo
    header = arquivo.read(len(apk_signature))

    # Verifica se o arquivo tem a assinatura de um APK e se a extensão é .apk
    if header == apk_signature and extensao.lower() == '.apk':
        return True
    else:
        return False


# ===============================================================================================


def Analises_estaticas(file_bytes, file_name):
    """
    Realiza a análise estática de um arquivo APK usando a API do VirusTotal.
    
    Args:
        file_bytes (bytes): Dados binários do arquivo APK.
        file_name (str): Nome do arquivo APK.
    
    Returns:
        tuple: Contém os resultados formatados para diferentes categorias de análise.
    """


    # ===============================================================================================
    # Configuração Inicial

    # URL para requisição da URL de upload
    url = "https://www.virustotal.com/api/v3/files/upload_url"

    # Informações do header com a chave API
    ApiKey = os.getenv('API_VT_KEY')
    print(ApiKey)
    headers = {
        "accept": "application/json",
        "x-apikey": ApiKey
    }

    # ===============================================================================================
    # Requisição da URL de upload


    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Verifica se houve um erro na requisição
    upload_url = response.json().get('data')
    print(response.json())
    print("="*100)
    print("="*100)
    print(upload_url)

    # Header file com os dados do arquivo de análise
    files = {
        "file": (file_name, file_bytes, "application/vnd.android.package-archive")
    }

    # Upload do arquivo
    response = requests.post(upload_url, files=files, headers=headers)
    response.raise_for_status()
    response_data = response.json()
    print("="*100)
    print("="*100)
    print("="*100)
    print("="*100)

    print(response_data)


    # ===============================================================================================
    # Espera a Análise e Requisição da Situação

    time.sleep(5)

    # Requisição da situação da análise
    url_response = response_data['data']['links']['self']
                                                                                     
    response = requests.get(url_response, headers=headers)
    response.raise_for_status()
    status_response = response.json()

    print("="*100)
    print(status_response)

    
    # ===============================================================================================

    print("="*100)
    print("="*100)
    print("="*100)
    print("="*100)

    try:
        # Hashs do arquivo
        contexto_hashs = status_response.get('meta', {}).get('file_info', {})
    except:
        contexto_hashs = {}

    
    # ===============================================================================================

    try:
        # Resultados gerais
        if response_data['data']['type'] == 'analysis':
            print(1)
            response = requests.get(status_response['data']['links']['item'], headers=headers)
            response.raise_for_status()
            analysis_result = response.json()
        elif response_data['data']['type'] == 'file':
            print(2)
            response = requests.get(status_response['data']['links']['self'], headers=headers)
            response.raise_for_status()
            analysis_result = response.json()
    except:
        print(3)
        response = requests.get(status_response['data']['links']['self'], headers=headers)
        response.raise_for_status()
        analysis_result = response.json()

    print(analysis_result)


    # ===============================================================================================
    # Processamento dos Atributos da Análise

    # Obtém atributos da análise
    attributes = analysis_result.get("data", {}).get("attributes", {})


    # Classificações atribuídas ao arquivo
    try:
        classificacao_ameaca = attributes.get("last_analysis_stats", {})
    except:
        classificacao_ameaca = {}


    # ===============================================================================================


    # Resultados de engines de antivirus
    try:
        antivirus_resultados = attributes.get("last_analysis_results", {})
    except:
        antivirus_resultados = {}

    
    # ===============================================================================================


    # Nível de ameaça para a rede
    try:
        rede_ameaca = attributes.get("crowdsourced_ids_stats", {})
    except:
        rede_ameaca = {}

    
    # ===============================================================================================


    # Contexto de rede (IP, URLs, Hosts) cadastrado por IDS
    contexto_rede = []
    for result in attributes.get("crowdsourced_ids_results", []):
        alert_context = result.get("alert_context")
        if alert_context and alert_context not in contexto_rede:
            contexto_rede.append(alert_context)


    # ===============================================================================================

    try:
        # Resultados do ANDROGUARD, como permissões e algumas strings URL
        androguard_infos_urls = attributes.get("androguard", {}).get("StringsInformation")
        androguard_infos_perm = attributes.get("androguard", {}).get("permission_details")

        perms_perigosas = {
            key: value for key, value in androguard_infos_perm.items()
            if 'dangerous' in value.get('permission_type', '')
        }
    except:
        androguard_infos_urls = []
        perms_perigosas = {}

    # Retorna os resultados formatados em um dicionário
    redes, redes_contexto, antivirus_results, classificacao, hashs_arquivo, urls, permissions = formatar_orm_bd(
        rede_ameaca, contexto_rede, classificacao_ameaca, antivirus_resultados, contexto_hashs, androguard_infos_urls, perms_perigosas
    )
    return redes, redes_contexto, antivirus_results, classificacao, hashs_arquivo, urls, permissions

    # ===============================================================================================

# ===============================================================================================


def formatar_orm_bd(rede_ameaca, contexto_rede, classificacao_ameaca, antivirus_resultados, contexto_hashs, androguard_infos_urls, perms_perigosas):
    """
    Formata os dados para o banco de dados.
    
    Args:
        rede_ameaca (dict): Dados sobre o nível de ameaça para a rede.
        contexto_rede (list): Dados sobre o contexto da rede.
        classificacao_ameaca (dict): Dados sobre a classificação de ameaça.
        antivirus_resultados (dict): Resultados dos antivírus.
        contexto_hashs (dict): Dados sobre os hashs do arquivo.
        androguard_infos_urls (list): Informações de URLs/Strings detectadas pelo ANDROGUARD.
        perms_perigosas (dict): Permissões potencialmente perigosas detectadas pelo ANDROGUARD.
    
    Returns:
        tuple: Dados formatados para o banco de dados.
    """
    
    # Formata os dados de 'rede_ameaca' para o campo no banco de dados
    rede_ameaca_bd = {
        'high': rede_ameaca.get('high', 0),
        'medium': rede_ameaca.get('medium', 0),
        'low': rede_ameaca.get('low', 0),
        'info': rede_ameaca.get('info', 0)
    }

    # Formata os dados de 'contexto_rede' para o campo no banco de dados
    contexto_rede_bd = [
        {
            'ip': entry.get('dest_ip', entry.get('src_ip', '')),
            'porta': entry.get('dest_port', entry.get('src_port', ''))
        } for context in contexto_rede for entry in context
    ]

    # Formata os dados de 'classificacao_ameaca' para o campo no banco de dados
    classificacao_ameaca_bd = {
        'malicious': classificacao_ameaca.get('malicious', 0),
        'suspicious': classificacao_ameaca.get('suspicious', 0),
        'undetected': classificacao_ameaca.get('undetected', 0),
        'harmless': classificacao_ameaca.get('harmless', 0),
        'timeout': classificacao_ameaca.get('timeout', 0),
        'confirmedtimeout': classificacao_ameaca.get('confirmed-timeout', 0),
        'failure': classificacao_ameaca.get('failure', 0),
        'typeunsupported': classificacao_ameaca.get('type-unsupported', 0)
    }

    # Formata os dados de 'antivirus_resultados' para o campo no banco de dados
    antivirus_resultados_bd = [
        {
            'engine': av_name,
            'method': av_info.get('method', ''),
            'version': av_info.get('engine_version', ''),
            'update': av_info.get('engine_update', ''),
            'category': av_info.get('category', ''),
            'result': av_info.get('result', '')
        } for av_name, av_info in antivirus_resultados.items()
    ]

    # Formata os dados de 'contexto_hashs' para o campo no banco de dados
    contexto_hashs_bd = [
        {
            'sha256': contexto_hashs.get('sha256', ''),
            'md5': contexto_hashs.get('md5', ''),
            'sha1': contexto_hashs.get('sha1', ''),
            'size': contexto_hashs.get('size', 0)
        }
    ]

    # Formata os dados de 'perms_perigosas' para o campo no banco de dados
    perms_perigosas_bd = [
        {
            'permission': perm,
            'permission_type': info['permission_type'],
            'short_description': info.get('short_description', ''),
        }
        for perm, info in perms_perigosas.items()
    ]

    # Formata os dados de 'androguard_infos_urls' para o campo no banco de dados
    urls_bd = [{'url': url} for url in androguard_infos_urls]

    return rede_ameaca_bd, contexto_rede_bd, classificacao_ameaca_bd, antivirus_resultados_bd, contexto_hashs_bd, urls_bd, perms_perigosas_bd

    # ===============================================================================================


# ===============================================================================================


# Esta função é responsável por analisar o arquivo APK
def analisar_arquivo(apk_file, user_id, nome_arquivo, extensao, flag_dinamica):
    """
    Analisa o arquivo APK fornecido, realiza uma análise estática utilizando a API do VirusTotal, AndroGuard e análise dinâmica,
    e salva os resultados da análise no banco de dados.

    Args:
        apk_file: Arquivo APK a ser analisado.
        user_id: ID do usuário que está realizando a análise.
        nome_arquivo: Nome do arquivo APK.
        extensao: Extensão do arquivo APK.
        flag_dinamica: Flag indicando se a análise deve incluir análise dinâmica.

    Returns:
        True se a análise e o salvamento no banco de dados forem bem-sucedidos, False caso contrário.

    """

    tempo_inicio = time.time()
    
    # ANÁLISES - ESTÁTICAS

    # Lendo os bytes do arquivo APK diretamente do upload
    apk_bytes = apk_file.read()

    try:
        # Chamando a função Analises_estaticas com os bytes do arquivo e o nome do arquivo
        frmt_redesameacas, frmt_contextorede, frmt_classificacao, frmt_antivirus, frmt_hashs, frmt_urls, frmt_perms = Analises_estaticas(apk_bytes, apk_file.name)
    except Exception as e:
        print(f"Erro ao realizar análise estática: {e}")
        return False

    # FIM DA ANÁLISE

    # Obtém o tempo após a geração do ID
    tempo_apos_geracao_id = time.time()

    # Calcula o tempo total de download e envio
    tempo_download_envio = calcular_tempo(tempo_inicio, tempo_apos_geracao_id)

    try:
        # Cria uma instância de AnaliseAPK no banco de dados
        analise_apk = AnaliseAPK.objects.create(
            usuario_id=user_id,
            nome=nome_arquivo,
            ext=extensao,
            status='Analisado',
            tempo=tempo_download_envio,
            virustotal={
                'AntivirusClassificacao': frmt_classificacao,
                'Antivirus': frmt_antivirus,
                'Redes': frmt_contextorede,
                'RedesClassificacao': frmt_redesameacas, 
                'Hashs': frmt_hashs
            },
            androguard={
                'urls': frmt_urls,
                'perms': frmt_perms
            }            
        )
        return True
    except Exception as e:
        print(f"Erro ao salvar análise no banco de dados: {e}")
        return False


# ==================================================================================================================
    

# Esta função é responsável por calcular o tempo decorrido
def calcular_tempo(tempo_inicio, tempo_fim):
    """
    Calcula o tempo decorrido entre o início e o fim e formata o resultado.

    Args:
        tempo_inicio: Tempo inicial em segundos desde a época.
        tempo_fim: Tempo final em segundos desde a época.

    Returns:
        String representando o tempo decorrido no formato "hh:mm:ss".
    """
    tempo_total = tempo_fim - tempo_inicio
    horas, resto = divmod(tempo_total, 3600)
    minutos, segundos = divmod(resto, 60)
    return f"{int(horas):02d}h:{int(minutos):02d}m:{int(segundos):02d}s"


# ==================================================================================================================


def converter_para_segundos(tempo):
    """
    Converte uma string de tempo no formato "hh:mm:ss" para segundos.

    Args:
        tempo: String no formato "hh:mm:ss".

    Returns:
        Total de segundos representado pela string de tempo.
    """
    partes_tempo = tempo.split(':')
    horas = int(partes_tempo[0].replace('h', ''))
    minutos = int(partes_tempo[1].replace('m', ''))
    segundos = int(partes_tempo[2].replace('s', ''))
    total_segundos = horas * 3600 + minutos * 60 + segundos
    return total_segundos


# ==================================================================================================================


def calc_media(analises_apk):
    """
    Calcula a média do tempo de análise para uma lista de análises.

    Args:
        analises_apk: Lista de objetos de análise APK com o campo 'tempo'.

    Returns:
        String representando o tempo médio no formato "hh:mm:ss".
    """
    total_segundos = 0
    total_analises = 0
    
    for analise in analises_apk:
        tempo_segundos = converter_para_segundos(analise.tempo)
        total_segundos += tempo_segundos
        total_analises += 1
    
    if total_analises == 0:
        return '00h:00m:00s' 
    
    media_segundos = total_segundos / total_analises
    
    media_horas = int(media_segundos // 3600)
    media_minutos = int((media_segundos % 3600) // 60)
    media_segundos = int(media_segundos % 60)
    
    media_formatada = f"{media_horas:02}h:{media_minutos:02}m:{media_segundos:02}s"
    
    return media_formatada


# ==================================================================================================================
