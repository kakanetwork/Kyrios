# ===============================================================================================

import os
import time
import hashlib
import requests
import logging.config


# ===============================================================================================

logger_error = logging.getLogger('error')
logger_info = logging.getLogger('info')

# ===============================================================================================


def vt_analise_estatica(apk_bytes, file_name):
    """
    Realiza a análise estática de um arquivo APK usando a API do VirusTotal.
    
    Args:
        apk_bytes (bytes): Dados binários do arquivo APK.
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
    headers = {
        "accept": "application/json",
        "x-apikey": ApiKey
    }

    # ===============================================================================================

    # Cria a HASH do arquivo em MD5 e verifica se já existe um relatório no VirusTotal
    file_hash = hashlib.md5(apk_bytes).hexdigest()
    url_file_report = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url_file_report, headers=headers)

    if response.status_code == 200:
        logger_info.info("Relatorio existente encontrado no VirusTotal.")
        status_response = response.json()

    # ===============================================================================================
    
    else:
        # Requisição da URL de upload
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Verifica se houve um erro na requisição
        upload_url = response.json().get('data')

        # Header file com os dados do arquivo de análise
        files = {
            "file": (file_name, apk_bytes, "application/vnd.android.package-archive")
        }

        # Upload do arquivo
        response = requests.post(upload_url, files=files, headers=headers)
        response.raise_for_status()
        response_data = response.json()

        # ===============================================================================================

        # Requisição da situação da análise
        url_response = response_data['data']['links']['self']
                                                                                        
        response = requests.get(url_response, headers=headers)
        response.raise_for_status()
        status_response = response.json()

        # Verificar se a análise está concluída
        while status_response.get('data', {}).get('attributes', {}).get('status') != 'completed':
            logger_info.info("Análise ainda em andamento... Aguardando mais tempo.")
            time.sleep(10)  # Espera mais tempo
            response = requests.get(url_response, headers=headers)
            response.raise_for_status()
            status_response = response.json()
    
    
    # ===============================================================================================

    try:
        # Resultados gerais
        if response_data['data']['type'] == 'analysis':
            response = requests.get(status_response['data']['links']['item'], headers=headers)
            response.raise_for_status()
            analysis_result = response.json()
        elif response_data['data']['type'] == 'file':
            response = requests.get(status_response['data']['links']['self'], headers=headers)
            response.raise_for_status()
            analysis_result = response.json()
    except:
        response = requests.get(status_response['data']['links']['self'], headers=headers)
        response.raise_for_status()
        analysis_result = response.json()

    # ===============================================================================================
    # Processamento dos Atributos da Análise

    # Obtém atributos da análise
    attributes = analysis_result.get("data", {}).get("attributes", {})

    # ===============================================================================================
    
    try:
        # Hashs do arquivo e tamanho (caso seja nova submissão)
        contexto_hashs = status_response.get('meta', {}).get('file_info', {})
        if not contexto_hashs:
            # Hashs do arquivo e tamanho (caso seja submissão existente)
            contexto_hashs = attributes
    except:
        contexto_hashs = {}

    # ===============================================================================================

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

    # try:
    #     # Resultados do ANDROGUARD, como permissões e algumas strings URL
    #     androguard_infos_urls = attributes.get("androguard", {}).get("StringsInformation")
    #     androguard_infos_perm = attributes.get("androguard", {}).get("permission_details")

    #     perms_perigosas = {
    #         key: value for key, value in androguard_infos_perm.items()
    #         if 'dangerous' in value.get('permission_type', '')
    #     }
    # except:
    #     androguard_infos_urls = []
    #     perms_perigosas = {}

    # Retorna os resultados formatados em um dicionário
    redes, redes_contexto, antivirus_results, classificacao, hashs_arquivo = formatar_orm_bd(
        rede_ameaca, contexto_rede, classificacao_ameaca, antivirus_resultados, contexto_hashs
    )

    return redes, redes_contexto, antivirus_results, classificacao, hashs_arquivo

    # ===============================================================================================

# ===============================================================================================


def formatar_orm_bd(rede_ameaca, contexto_rede, classificacao_ameaca, antivirus_resultados, contexto_hashs):
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

    return rede_ameaca_bd, contexto_rede_bd, classificacao_ameaca_bd, antivirus_resultados_bd, contexto_hashs_bd

    # ===============================================================================================

