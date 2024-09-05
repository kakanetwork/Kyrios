from datetime import datetime
import os, hashlib

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

def formatar_data(dt):
    if isinstance(dt, list):
        return [d.strftime('%Y-%m-%d %H:%M:%S') if isinstance(d, datetime) else str(d) for d in dt]
    elif isinstance(dt, datetime):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return str(dt)

# ===============================================================================================


def salvar_apk(apk_file, apk_bytes, caminho_base='./kyapp/analysis/apks'):
    """
    Salva um arquivo APK no diretório especificado com um nome baseado em seu hash SHA-256.

    Esta função cria um hash SHA-256 do conteúdo do arquivo APK para gerar um nome único para o arquivo salvo. 
    O diretório de destino é criado se não existir. O arquivo APK é salvo no diretório com o nome baseado no hash.

    Args:
        apk_file (File): Objeto de arquivo enviado contendo o APK a ser salvo.
        apk_bytes (bytes): Conteúdo do arquivo APK em formato de bytes.
        caminho_base (str): Diretório onde o APK será salvo. O padrão é './kyapp/analysis/apks'.

    Returns:
        str: Caminho completo do arquivo APK salvo.
    """
    
    # Cria um hash SHA-256 do conteúdo do APK
    hash_sha256 = hashlib.sha256(apk_bytes).hexdigest()
    
    # Gera o caminho completo para salvar o APK, com o hash como nome do arquivo
    caminho_completo = os.path.join(caminho_base, f'{hash_sha256}.apk')
    
    # Cria o diretório se não existir
    os.makedirs(caminho_base, exist_ok=True)
    
    # Salva o APK no diretório
    with open(caminho_completo, 'wb+') as destino:
        for chunk in apk_file.chunks():
            destino.write(chunk)
    
    return caminho_completo, hash_sha256


# ===============================================================================================

def excluir_apk(caminho_arquivo):
    """
    Exclui permanentemente o arquivo APK do diretório.

    Args:
        caminho_arquivo (str): Caminho do arquivo APK a ser excluído.
    
    Returns:
        bool: True se o arquivo foi excluído com sucesso, False caso contrário.
    """
    try:
        # Verifica se o arquivo existe
        if os.path.exists(caminho_arquivo):
            os.remove(caminho_arquivo)
            return True
        else:
            return False
    except Exception as e:
        return False


# ===============================================================================================
