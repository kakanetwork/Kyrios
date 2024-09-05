# ===============================================================================================


from pyaxmlparser import APK
import json
from dotenv import load_dotenv
import os

load_dotenv()


# ===============================================================================================


def leitura_manifesto_perms(caminho_apk):
    """
    Lê o manifesto e as permissões de um APK a partir de bytes.

    Args:
        apk_bytes (bytes): Conteúdo do arquivo APK em formato de bytes.

    Returns:
        dict: Dois dicionários JSON separados, um para permissões padrão e outro para permissões personalizadas.
    """

    # Caminho relativo ajustado, dependendo da localização do script e do arquivo JSON
    arq_perms_detalhes = os.getenv('PATH_JSON_DETALHES')

    # Cria um objeto BytesIO a partir dos bytes do APK
    #apk_file = io.BytesIO(apk_bytes)

    apk = APK(caminho_apk)

    permissoes = apk.get_permissions()  # Obtém permissões do aplicativo
    permissoes_detalhadas, permissoes_declaradas = obter_permissoes_detalhadas(permissoes, arq_perms_detalhes)
    permissoes_declaradas_2 = apk.get_declared_permissions()  # Obtém permissões declaradas pelo aplicativo

    # isso server para pegar permissões que são declaradas e possam está em nas permissões gerais do APK
    permissoes_declaradas.extend(permissoes_declaradas_2)
 
    return permissoes_detalhadas, permissoes_declaradas

# ===============================================================================================


def carregar_detalhes_permissoes(caminho_arquivo):
    """
    Carrega detalhes das permissões a partir do arquivo JSON.

    Args:
        caminho_arquivo: Caminho para o arquivo JSON com detalhes das permissões.
    Returns:    
        Lista de dicionários com detalhes das permissões.

    """
    # Abre o arquivo JSON para leitura com codificação UTF-8
    with open(caminho_arquivo, 'r', encoding='utf-8') as arquivo:
        # Carrega e retorna o conteúdo do arquivo JSON
        return json.load(arquivo)
    

# ===============================================================================================


def obter_permissoes_detalhadas(permissoes, caminho_arquivo):
    """
    Substitui permissões por informações detalhadas a partir de um arquivo JSON, para melhor visualização

    Args:
        permissoes: Lista de permissões obtidas.
        caminho_arquivo: Caminho para o arquivo JSON com detalhes das permissões.
    Returns:
        Lista de permissões detalhadas e lista de permissões não detalhadas.adas.
    """

    # Carrega os detalhes das permissões do arquivo JSON
    detalhes_permissoes = carregar_detalhes_permissoes(caminho_arquivo)
    
    # Cria um dicionário para busca rápida dos detalhes
    dicionario_detalhes = {item['constant_value']: item for item in detalhes_permissoes}
    
    # Listas para armazenar permissões detalhadas e não detalhadas
    permissoes_detalhadas = []
    permissoes_nao_detalhadas = []
    
    # Itera sobre cada permissão obtida
    for permissao in permissoes:
        # Verifica se a permissão inicia com 'android.permission' ou 'com.android'
        if permissao.startswith('android.permission') or permissao.startswith('com.android'):
            # Verifica se há detalhes para a permissão no dicionário
            if permissao in dicionario_detalhes:
                # Adiciona os detalhes da permissão se encontrados
                permissoes_detalhadas.append(dicionario_detalhes[permissao])
            else:
                # Se não encontrado, adiciona uma entrada padrão com descrição e nível desconhecido
                permissoes_detalhadas.append({
                    "name": permissao.rsplit('.', 1)[-1], # pega apenas o nome da permissão
                    "description": "Descrição não disponível para esta permissão.",
                    "protection_level": "Desconhecido",
                    "constant_value": permissao
                })
        else:
            # Adiciona permissões que não são detalhadas à lista separada
            permissoes_nao_detalhadas.append(permissao)
    
    # Retorna duas listas: permissões detalhadas e permissões não detalhadas
    return permissoes_detalhadas, permissoes_nao_detalhadas

# ===============================================================================================
