import re
from urllib.parse import urlparse
import whois
import json
from datetime import datetime 

# ===============================================================================================

def analise_urls(apk_zip):
    """
    Analisa um arquivo APK para identificar URLs válidas e possíveis strings maliciosas.

    Args:
        apk_bytes (bytes): Dados binários do arquivo APK.

    Returns:
        set: Um conjunto de URLs válidas encontradas no arquivo APK.

    """
    try:
        # Listar todos os arquivos no APK
        arquivos_apk = apk_zip.namelist()
        todas_as_strings = []

        # Iterar sobre os arquivos no APK
        for arquivo in arquivos_apk:
            if arquivo:
                # Processar cada arquivo no APK
                with apk_zip.open(arquivo, 'r') as f:
                    conteudo_bytes = f.read()  # Ler o conteúdo do arquivo como bytes
                    conteudo_str = conteudo_bytes.decode('utf-8', errors='ignore')  # Decodificar bytes para string
                    # Extrair sequências de caracteres legíveis (potenciais strings)
                    # Regex: Captura sequências de caracteres que não são caracteres de controle
                    strings_extraidas = re.findall(r'[^\x00-\x1F\x7F-\xFF]{4,}', conteudo_str)
                    todas_as_strings.extend(strings_extraidas)  # Adicionar strings encontradas à lista

        # Definir padrões para identificar strings potencialmente maliciosas
        padrões_maliciosos = [
            r'[hH][tT]{2}[pP]://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',  # URLs
            r'cmd.exe',  # Comando do Windows
            r'\b(?:exec|eval|shell_exec|system|passthru|popen)\b'  # Funções potencialmente perigosas
        ]
        
        # Encontrar strings que correspondem aos padrões maliciosos
        strings_encontradas = set()
        for linha in todas_as_strings:
            for padrão in padrões_maliciosos:
                strings_encontradas.update(re.findall(padrão, linha))
        
        # Regex para encontrar URLs completas e válidas
        padrão_url = re.compile(
            r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F])){4,}'
        )
        urls = set(padrão_url.findall('\n'.join(strings_encontradas)))  # Encontrar todas as URLs

        # Filtrar URLs inválidas
        urls_validas = set()
        for url in urls:
            if not url.lower().endswith('.png'):  # Excluir URLs que terminam com ".png"
                url_analisada = urlparse(url)  # Analisar a URL
                if url_analisada.scheme in ['http', 'https'] and url_analisada.netloc:
                    # Verificar se a URL possui um domínio e um TLD válidos
                    partes_caminho = url_analisada.path.strip('/').split('.')
                    if len(partes_caminho) > 1:
                        urls_validas.add(url)  # Adicionar URL válida ao conjunto
        
        return list(urls_validas)

    except Exception as e:
        return


# ===============================================================================================


def whois_urls(urls_dict):
    """
    Consulta informações WHOIS para uma lista de URLs e retorna uma lista de dicionários com os dados obtidos.
    
    Args:
    - urls_dict (list): Uma lista de URLs para as quais as informações WHOIS serão consultadas.

    Return:
    - list: Uma lista de dicionários, onde cada dicionário contém informações WHOIS sobre um domínio

    """
    info_urls = []  # Lista para armazenar os resultados das consultas WHOIS

    for url in urls_dict:
        try:
            # Extrai o domínio da URL removendo o protocolo e caminhos adicionais
            domain = url.split('//')[-1].split('/')[0]

            # Realiza a consulta WHOIS
            info = whois.whois(domain)

            # Adiciona as informações WHOIS obtidas à lista
            info_urls.append(info)

        except Exception as e:
            # Em caso de erro, exibe uma mensagem de erro e continua para a próxima URL
            continue

    # Função para converter objetos datetime para strings em formato ISO, necessária para serializar o JSON
    def ajustar_data(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()  # Converte datetime para string em formato ISO
        raise TypeError(f"Tipo não serializável: {type(obj)}")  # Levanta erro se o tipo não for serializável

    info_urls_serialized = []  # Lista para armazenar os dados serializados

    for item in info_urls:
        # Serializa o objeto WHOIS convertendo todos os datetime para strings
        item_serialized = json.loads(json.dumps(item, default=ajustar_data))
        info_urls_serialized.append(item_serialized)

    # Retorna a lista de informações WHOIS serializadas
    return info_urls_serialized

# ===============================================================================================
