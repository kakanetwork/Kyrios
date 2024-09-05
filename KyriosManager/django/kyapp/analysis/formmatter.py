import re

# ===============================================================================================

def formatar_dumpsys(permissoes_ad):
    """
    Extrai informações e formata a saída do comando dumpsys.

    Args:
        permissoes_ad (str): A saída do comando dumpsys como uma string.

    Returns:
        dict: Um dicionário com informações extraídas e formatadas.
    """
    # Inicializa o dicionário para armazenar as informações extraídas
    dados_extraidos = {
        "userId": None,
        "gid": None,
        "codePath": None,
        "resourcePath": None,
        "primaryCpuAbi": None,
        "secondaryCpuAbi": None,
        "informacoes_versao": None,
        "dataDir": None,
        "execucao": {
            "instalado": None,
            "oculto": None,
            "suspenso": None,
            "parado": None,
            "naoLancado": None,
            "ativado": None,
            "instantaneo": None,
        },
        "permissoes_instalacao": {}
    }

    # Extrai userId
    frmt_userId = re.search(r'userId=(\d+)', permissoes_ad)
    if frmt_userId:
        dados_extraidos["userId"] = frmt_userId.group(1)
    
    # Extrai GIDs
    frmt_gids = re.search(r'gids=\[(.*?)\]', permissoes_ad)
    if frmt_gids:
        dados_extraidos["gid"] = frmt_gids.group(1)

    # Extrai codePath
    frmt_codePath = re.search(r'codePath=(\S+)', permissoes_ad)
    if frmt_codePath:
        dados_extraidos["codePath"] = frmt_codePath.group(1)

    # Extrai resourcePath
    frmt_resourcePath = re.search(r'resourcePath=(\S+)', permissoes_ad)
    if frmt_resourcePath:
        dados_extraidos["resourcePath"] = frmt_resourcePath.group(1)

    # Extrai primaryCpuAbi
    frmt_primaryCpuAbi = re.search(r'primaryCpuAbi=(\S+)', permissoes_ad)
    if frmt_primaryCpuAbi:
        dados_extraidos["primaryCpuAbi"] = frmt_primaryCpuAbi.group(1)

    # Extrai secondaryCpuAbi
    frmt_secondaryCpuAbi = re.search(r'secondaryCpuAbi=(\S+)', permissoes_ad)
    if frmt_secondaryCpuAbi:
        dados_extraidos["secondaryCpuAbi"] = frmt_secondaryCpuAbi.group(1)

    # Extrai informações de versão (versionCode, minSdk, targetSdk)
    frmt_versao = re.search(r'versionCode=(\d+) minSdk=(\d+) targetSdk=(\d+)', permissoes_ad)
    if frmt_versao:
        dados_extraidos["informacoes_versao"] = {
            "versionCode": frmt_versao.group(1),
            "minSdk": frmt_versao.group(2),
            "targetSdk": frmt_versao.group(3)
        }

    # Extrai dataDir
    frmt_dataDir = re.search(r'dataDir=(\S+)', permissoes_ad)
    if frmt_dataDir:
        dados_extraidos["dataDir"] = frmt_dataDir.group(1)

    # Extrai informações de execução
    frmt_execucao = re.search(r'User \d+: ceDataInode=.* instalado=(\w+) oculto=(\w+) suspenso=(\w+) parado=(\w+) naoLancado=(\w+) ativado=(\w+) instantaneo=(\w+)', permissoes_ad)
    if frmt_execucao:
        dados_extraidos["execucao"] = {
            "instalado": frmt_execucao.group(1),
            "oculto": frmt_execucao.group(2),
            "suspenso": frmt_execucao.group(3),
            "parado": frmt_execucao.group(4),
            "naoLancado": frmt_execucao.group(5),
            "ativado": frmt_execucao.group(6),
            "instantaneo": frmt_execucao.group(7)
        }

    # Extrai permissões de instalação
    frmt_permissoes = re.findall(r'(\S+): granted=(\w+)', permissoes_ad)
    if frmt_permissoes:
        for perm, concedida in frmt_permissoes:
            dados_extraidos["permissoes_instalacao"][perm] = concedida

    return dados_extraidos

# ===============================================================================================

def formatar_logcat(logcat_texto, processos_ids, termos_buscados):
    """
    Procura por linhas no texto do logcat que contenham qualquer um dos processos_ids
    ou termos_buscados (UID, GID, PACKAGE_NAME, ou NUMERO DO PROCESSO).

    Args:
        logcat_texto (str): O texto do logcat a ser pesquisado.
        processos_ids (list): Lista de IDs de processos para procurar.
        termos_buscados (list): Lista de termos que devem ser encontrados nas linhas.

    Returns:
        dict: Dicionário contendo o número da linha e o texto da linha correspondente.
    """
    # Converter o texto do logcat em uma lista de linhas
    linhas = logcat_texto.split('\n')

    # Dicionário para armazenar os resultados
    resultados = {}

    # Iterar sobre cada linha do logcat
    for numero_linha, linha in enumerate(linhas):
        linha_completa = linha.strip()  # Remover espaços em branco no início e no fim da linha

        # Verificar se algum dos termos buscados está presente na linha
        for termo in termos_buscados:
            if termo in linha_completa:
                resultados[numero_linha + 1] = linha_completa  # Armazenar no dicionário o número da linha e o texto

        # Verificar se o ID de processo está presente na linha
        for pid in processos_ids:
            if str(pid) in linha_completa:
                resultados[numero_linha + 1] = linha_completa  # Armazenar no dicionário o número da linha e o texto

    return resultados