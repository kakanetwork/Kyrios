# ===============================================================================================

import os
import time
import platform
import threading
import subprocess
import logging.config
from dotenv import load_dotenv
from .formmatter import formatar_dumpsys, formatar_logcat

# ===============================================================================================

load_dotenv() # Carrega variáveis de ambiente do arquivo .env
caminho_adb = os.getenv('CAMINHO_ADB') # Caminho completo para o adb.exe (Android Debug Bridge)
adb_lock = threading.Lock()  # Lock para garantir que apenas uma conexão ADB esteja ativa por vez
adb_conectado = False  # Flag para indicar se há uma conexão ativa

# ===============================================================================================

logger_error = logging.getLogger('error')
logger_info = logging.getLogger('info')

# ===============================================================================================

def executar_comando_adb(comando):
    """
    Executa um comando ADB e retorna a saída.

    Args:
        comando (str): O comando ADB a ser executado.

    Returns:
        str: A saída do comando ADB. Se houver erro, retorna None.
    """
    try:
        comando_completo = f'"{caminho_adb}" {comando}'  # Monta o comando completo incluindo o caminho do ADB
        resultado = subprocess.run(comando_completo, shell=True, check=True, text=True, capture_output=True, encoding='utf-8')
        return resultado.stdout  # Retorna a saída do comando executado
    except subprocess.CalledProcessError as e:
        logger_error.critical(f"Erro ao executar comando: {str(e)}")
        return None  # Em caso de erro na execução do comando, retorna None
    
# ===============================================================================================

def iniciar_tcpdump_adb(dispositivo, caminho_remoto_pcap):
    try:

        if platform.system() == "Windows":
            # No Windows, execute tcpdump em um novo processo com o & no final
            comando = f"{caminho_adb} -s {dispositivo} shell tcpdump -i any -w {caminho_remoto_pcap}"
            subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            # No Linux, execute tcpdump em um novo processo
            comando = f"{caminho_adb} -s {dispositivo} shell tcpdump -i any -w {caminho_remoto_pcap} &"
            subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    except Exception as e:
        logger_error.critical(f"Erro ao iniciar a captura de pacotes: {str(e)}")

# ===============================================================================================

def conectar_adb(dispositivo):
    """
    Conecta ao ADB e retorna True se a conexão for bem-sucedida.

    Args:
        dispositivo (str): O identificador (IP ou ID) do dispositivo a ser conectado.

    Returns:
        bool: True se a conexão for bem-sucedida, False caso contrário.
    """
    global adb_conectado

    if adb_conectado:
        logger_info.debug("Já existe um ADB conectado.")
        return False  # Retorna False se já houver uma conexão ativa

    with adb_lock:  # Utiliza um lock para garantir que apenas uma conexão ADB seja feita por vez
        if adb_conectado:
            logger_info.debug("Já existe um ADB conectado.")
            return False  # Retorna False se uma conexão for estabelecida enquanto esperávamos

        # Tenta conectar ao dispositivo ADB
        try:
            executar_comando_adb(f"connect {dispositivo}:5555")
        except Exception as e:
            logger_error.critical(f"Erro ao conectar com o emulador: {dispositivo}:{str(e)}")
            return False  # Retorna False se houver falha ao conectar

        # Verifica se o dispositivo está conectado
        dispositivos_output = executar_comando_adb("devices")
        if dispositivos_output and dispositivo in dispositivos_output:
            adb_conectado = True  # Marca como conectado se o dispositivo estiver na lista
            logger_info.info(f"Conectado ao emulador: {dispositivo}")
            return True
        else:
            logger_error.error(f"Erro ao conectar com o emulador: {dispositivo}:{str(e)}")
            return False  # Retorna False se o dispositivo não estiver conectado

# ===============================================================================================


def desconectar_adb(dispositivo):
    """
    Desconecta do ADB e libera o lock, indicando que a conexão foi encerrada.

    Args:
        dispositivo (str): O identificador (IP ou ID) do dispositivo a ser desconectado.

    Returns:
        None
    """
    
    global adb_conectado
    with adb_lock:
        if adb_conectado:
            executar_comando_adb(f"-s {dispositivo} disconnect {dispositivo}:5555")
            adb_conectado = False

# ===============================================================================================

def gerenciador_adb(abi, caminho_apk, hash_sha256, nome_pacote, apk_id):
    """
    Função para analisar um pacote APK em um emulador Android conectado via ADB.

    Args:
        abi (str): ABI do emulador (x86 ou x86_64).
        caminho_apk (str): Caminho local para o arquivo APK a ser analisado.
        hash_sha256 (str): Hash SHA-256 do APK para gerar nome único no dispositivo.
        nome_pacote (str): Nome completo do pacote do aplicativo (ex.: com.exemplo.app).

    Returns:
        Tuple: Status da operação, dumpsys_bd (dict), logcat_bd (dict), arquivos_modificados (list), mensagem_erro (str)
    """
    # ===============================================================================================

    # Nome único para o APK no dispositivo
    hash_nome_id = f"{hash_sha256}_{apk_id}" 
    # Inicializa os dicionários e a lista que serão retornados em caso de erro
    dumpsys_bd = {}
    logcat_bd = {}
    arquivos_modificados = []
    # IPs dos dispositivos x86 e x86_64 configurados no .env
    ip_x86_64_disp = os.getenv('IP_x86_64_DISP')
    ip_x86_32_disp = os.getenv('IP_x86_32_DISP')
    # Define o caminho remoto do APK no dispositivo emulador
    caminho_remoto_apk = f"/sdcard/{hash_nome_id}.apk"
    caminho_remoto_pcap = f"/sdcard/captura_de_rede_{hash_nome_id}.pcap"
    # Caminho local onde os arquivos serão salvos
    caminho_local_pcap = os.getenv("CAMINHO_LOCAL_PCAP") 
    caminho_upload_pcap = f"{caminho_local_pcap}/captura_de_rede_{hash_nome_id}.pcap"
    # Máximo de tentativas para verificar a instalação do APK
    max_tentativas = 5  

    # ===============================================================================================

    # Define o dispositivo e ABI com base na flag 'abi'
    if abi:
        dispositivo = ip_x86_32_disp  # IP ou identificador do emulador para x86
    else:
        dispositivo = ip_x86_64_disp  # IP ou identificador do emulador para x86_64

    # ===============================================================================================

    # Conecta ao dispositivo via ADB
    if conectar_adb(dispositivo):
        try:
            # ===============================================================================================

            # Envia o APK para o emulador
            executar_comando_adb(f"-s {dispositivo} push {caminho_apk} {caminho_remoto_apk}")
            logger_info.info(f"APK enviado para o emulador: {dispositivo}")            

            # ===============================================================================================

            # Captura pacotes de rede gerados pelo pacote usando tcpdump
            try:
                iniciar_tcpdump_adb(dispositivo, caminho_remoto_pcap)
                logger_info.info("Pacotes de rede capturados usando tcpdump")                
            except Exception as e:
                logger_error.error(f"Erro ao capturar pacotes de rede: {e}")
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao capturar pacotes de rede: {e}", caminho_upload_pcap
            
            # ===============================================================================================

            try:
                # Instala o APK no emulador
                executar_comando_adb(f"-s {dispositivo} shell pm install {caminho_remoto_apk}")
                logger_info.info("Tentativa de instalação do APK no emulador")
            except Exception as e:
                logger_error.error(f"Erro ao instalar o APK: {e}")
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao instalar o APK, a Arquitetura do seu APK possui modificações não válidas para Análise: {e}", caminho_upload_pcap
    
            # ===============================================================================================

            # Verifica se o pacote foi instalado com sucesso
            for i in range(max_tentativas):
                pacotes_instalados = executar_comando_adb(f"-s {dispositivo} shell pm list packages")
                if f"package:{nome_pacote}" in pacotes_instalados:
                    logger_info.info('Apk verificado e instalado')
                    break
                time.sleep(4)
            else:
                logger_info.info("APK nao instalado")
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, "", caminho_upload_pcap
            
            # ===============================================================================================

            # Captura informações do pacote instalado usando dumpsys
            try:
                saida_dumpsys = executar_comando_adb(f'-s {dispositivo} shell dumpsys package {nome_pacote}')
                logger_info.info("Informações do pacote capturadas usando dumpsys")
                dumpsys_bd = formatar_dumpsys(saida_dumpsys)
            except Exception as e:
                logger_error.error(f"Erro ao capturar dumpsys: {e}")
                return False, {}, {}, [], f"Erro ao capturar dumpsys: {e}", caminho_upload_pcap

            # ===============================================================================================
            
            # Captura os logs do pacote
            try:
                saida_logcat = executar_comando_adb(f"-s {dispositivo} logcat -d")
                logger_info.info("Logs do APK capturados.")
                logcat_bd = formatar_logcat(saida_logcat, [dumpsys_bd.get("userId"), dumpsys_bd.get("gid")], [nome_pacote])
            except Exception as e:
                logger_error.error(f"Erro ao capturar logcat: {e}")
                return False, dumpsys_bd, {}, [], f"Erro ao capturar logcat: {e}", caminho_upload_pcap

            # ===============================================================================================
            
            # Verifica arquivos modificados ou criados pelo pacote

            # Define os diretórios a serem verificados
            diretorios = ['/sdcard', '/system', '/sys', '/data', '/cache', '/storage', '/mnt', '/data/app', '/data/user']

            # Verifica arquivos modificados ou criados pelo pacote em cada diretório
            for diretorio in diretorios:
                try:
                    comando = f"-s {dispositivo} shell find {diretorio} -name '*{nome_pacote}*'"
                    resultado = executar_comando_adb(comando)
                    arquivos_modificados.extend(resultado.splitlines())
                    logger_info.info(f"Arquivos modificados ou criados no diretorio {diretorio} verificados")
                except Exception as e:
                    logger_error.error(f"Erro ao verificar arquivos modificados no diretorio {diretorio}: {e}")
                    return False, dumpsys_bd, logcat_bd, [], f"Erro ao verificar arquivos modificados no diretório {diretorio}: {e}", caminho_upload_pcap

            # ===============================================================================================
            
            # Desinstala o pacote do emulador após a análise
            try:
                executar_comando_adb(f"-s {dispositivo} uninstall {nome_pacote}")
                logger_info.info("Pacote desinstalado do emulador")
            except Exception as e:
                logger_error.critical(f"Erro ao desinstalar o pacote: {e}")
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao desinstalar o pacote: {e}", caminho_upload_pcap
            
            # ===============================================================================================
            
            executar_comando_adb(f"-s {dispositivo} shell pkill tcpdump")
            logger_info.info("Captura de pacotes parada.")
            
            # ===============================================================================================

            # Limpa os dados residuais do pacote
            try:
                executar_comando_adb(f"-s {dispositivo} shell pm clear {nome_pacote}")
                logger_info.info("Dados residuais do pacote limpos")
            except Exception as e:
                logger_error.error(f"Erro ao limpar dados residuais: {e}")
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao limpar dados residuais: {e}", caminho_upload_pcap

            # ===============================================================================================

            #Transfere a captura de pacotes de rede para o computador local
            try:
                executar_comando_adb(f"-s {dispositivo} pull {caminho_remoto_pcap} {caminho_local_pcap}")
                logger_info.info("Captura de pacotes de rede transferida para o computador local")
            except Exception as e:
                logger_error.critical(f"Erro ao limpar dados residuais: {e}")
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao transferir captura de pacotes de rede: {e}", caminho_upload_pcap

            # ===============================================================================================

        except Exception as e:
            # Remover o APK do dispositivo em caso de erro e retornar um dicionário vazio
            executar_comando_adb(f"-s {dispositivo} uninstall {nome_pacote}")
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_apk}")
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_pcap}")
            desconectar_adb(dispositivo)
            logger_error.critical(f"Ocorreu um erro durante a análise do pacote: {e}")
            return False, {}, {}, [], f"Ocorreu um erro durante a análise do pacote: {e}", caminho_upload_pcap

        # ===============================================================================================

        finally:
            # Desconecta do dispositivo
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_pcap}")
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_apk}")
            desconectar_adb(dispositivo)
            logger_info.info("Análise Finalizada.")

        # ===============================================================================================
    else:
        return False, {}, {}, [], f"Não foi possivel fechar a conexão", caminho_upload_pcap  # Retorna as variáveis capturadas

    return True, dumpsys_bd, logcat_bd, arquivos_modificados, "", caminho_upload_pcap  # Retorna as variáveis capturadas

# ===============================================================================================
