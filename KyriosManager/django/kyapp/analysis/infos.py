# ===============================================================================================

from pyaxmlparser import APK

# ===============================================================================================

def infos_apk(caminho_apk):
    """
    Extrai informações do arquivo APK e organiza os resultados.

    Args:
        apk_bytes (bytes): Arquivo APK.

    Returns:
        dict: Um dicionário contendo informações do APK
    """
    
    #apk_file = io.BytesIO(caminho_apk)
  
    # Carregar o APK usando a biblioteca pyaxmlparser
    apk = APK(caminho_apk)
    
    # Extrair e organizar as informações do APK
    nome_do_pacote = apk.get_package()                # Nome do pacote
    atividade_principal = apk.get_main_activity()    # Atividade principal
    todas_atividades = apk.get_activities()          # Lista de todas as atividades
    todos_servicos = apk.get_services()               # Lista de todos os serviços

    
    return nome_do_pacote, atividade_principal, todas_atividades, todos_servicos

# ===============================================================================================


def abis_apk(apk):
    """
    Identifica as ABIs (Application Binary Interfaces) suportadas por um APK, 
    analisando os arquivos na pasta 'lib/' dentro do APK.

    Args:
        apk (ZipFile): Um objeto `ZipFile` que representa o arquivo APK. 
    Returns:
        set: Um conjunto contendo as ABIs identificadas no APK. 

    """
    
    abis = set()

    for arquivos in apk.infolist():
        # Verifica se o caminho do arquivo começa com 'lib/'
        if arquivos.filename.startswith('lib/'):
            # Extrai a ABI do caminho do arquivo
            partes = arquivos.filename.split('/')
            if len(partes) > 1:
                abi = partes[1]
                if abi in {'armeabi', 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64', 'mips', 'mips64'}:
                    abis.add(abi)
                    
    return list(abis)

# ===============================================================================================
