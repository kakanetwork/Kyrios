import subprocess
import threading
import time
import os
from dotenv import load_dotenv
from .formmatter import formatar_dumpsys, formatar_logcat
import platform

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()

# Caminho completo para o adb.exe (Android Debug Bridge)
caminho_adb = os.getenv('CAMINHO_ADB')

# Variável para controlar o estado da conexão ADB
adb_lock = threading.Lock()  # Lock para garantir que apenas uma conexão ADB esteja ativa por vez
adb_conectado = False  # Flag para indicar se há uma conexão ativa

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
        print("Captura de pacotes iniciada com tcpdump")
    except Exception as e:
        print(f"Erro ao iniciar a captura de pacotes: {e}")


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
        print("Já há uma conexão ativa")
        return False  # Retorna False se já houver uma conexão ativa

    with adb_lock:  # Utiliza um lock para garantir que apenas uma conexão ADB seja feita por vez
        if adb_conectado:
            print("Uma conexão foi estabelecida enquanto esperávamos")
            return False  # Retorna False se uma conexão for estabelecida enquanto esperávamos

        # Tenta conectar ao dispositivo ADB
        try:
            print(f"Tentando conectar ao dispositivo {dispositivo}")
            output = executar_comando_adb(f"connect {dispositivo}:5555")
        except Exception as e:
            print(f"Falha ao conectar ao dispositivo: {e}")
            return False  # Retorna False se houver falha ao conectar

        # Verifica se o dispositivo está conectado
        dispositivos_output = executar_comando_adb("devices")
        if dispositivos_output and dispositivo in dispositivos_output:
            adb_conectado = True  # Marca como conectado se o dispositivo estiver na lista
            print("Conexão ADB estabelecida com sucesso")
            return True
        else:
            print("Dispositivo não está conectado")
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

    hash_nome_id = f"{hash_sha256}_{apk_id}"  # Nome único para o APK no dispositivo
    print("aaaaaaaaaa")
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

    max_tentativas = 5  # Máximo de tentativas para verificar a instalação do APK

    # Define o dispositivo e ABI com base na flag 'abi'
    if abi:
        print("aq")
        dispositivo = ip_x86_32_disp  # IP ou identificador do emulador para x86
    else:
        print("aq3")
        dispositivo = ip_x86_64_disp  # IP ou identificador do emulador para x86_64

    # ===============================================================================================

    # Conecta ao dispositivo via ADB
    if conectar_adb(dispositivo):
        try:
            # ===============================================================================================

            print("Conexão ADB estabelecida com sucesso")
            # Envia o APK para o emulador
            executar_comando_adb(f"-s {dispositivo} push {caminho_apk} {caminho_remoto_apk}")
            print("APK enviado para o emulador")

            # ===============================================================================================

            # Captura pacotes de rede gerados pelo pacote usando tcpdump
            try:
                iniciar_tcpdump_adb(dispositivo, caminho_remoto_pcap)
                print("Pacotes de rede capturados usando tcpdump")
            except Exception as e:
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao capturar pacotes de rede: {e}", caminho_upload_pcap
            
            # ===============================================================================================

            try:
                # Instala o APK no emulador
                executar_comando_adb(f"-s {dispositivo} shell pm install {caminho_remoto_apk}")
                print("APK instalado no emulador")
            except Exception as e:
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao instalar o APK, a Arquitetura do seu APK possui modificações não válidas para Análise: {e}", caminho_upload_pcap
    
            # ===============================================================================================

            # Verifica se o pacote foi instalado com sucesso
            for i in range(max_tentativas):
                pacotes_instalados = executar_comando_adb(f"-s {dispositivo} shell pm list packages")
                if f"package:{nome_pacote}" in pacotes_instalados:
                    print('foi')
                    break
                time.sleep(4)
            else:
                print("Não foi", pacotes_instalados)
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, "", caminho_upload_pcap
            
            # ===============================================================================================

            # Captura informações do pacote instalado usando dumpsys
            try:
                saida_dumpsys = executar_comando_adb(f'-s {dispositivo} shell dumpsys package {nome_pacote}')
                print("Informações do pacote capturadas usando dumpsys")
                dumpsys_bd = formatar_dumpsys(saida_dumpsys)
            except Exception as e:
                return False, {}, {}, [], f"Erro ao capturar dumpsys: {e}", caminho_upload_pcap

            # ===============================================================================================
            
            # Captura os logs do pacote
            try:
                saida_logcat = executar_comando_adb(f"-s {dispositivo} logcat -d")
                print("Logs do pacote capturados")
                logcat_bd = formatar_logcat(saida_logcat, [dumpsys_bd.get("userId"), dumpsys_bd.get("gid")], [nome_pacote])
            except Exception as e:
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
                    print(f"Arquivos modificados ou criados no diretório {diretorio} verificados")
                except Exception as e:
                    return False, dumpsys_bd, logcat_bd, [], f"Erro ao verificar arquivos modificados no diretório {diretorio}: {e}", caminho_upload_pcap

            # ===============================================================================================
            
            # Desinstala o pacote do emulador após a análise
            try:
                executar_comando_adb(f"-s {dispositivo} uninstall {nome_pacote}")
                print("Pacote desinstalado do emulador")
            except Exception as e:
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao desinstalar o pacote: {e}", caminho_upload_pcap
            
            executar_comando_adb(f"-s {dispositivo} shell pkill tcpdump")
            print("Captura de pacotes parada.")
            
            # ===============================================================================================

            # Limpa os dados residuais do pacote
            try:
                executar_comando_adb(f"-s {dispositivo} shell pm clear {nome_pacote}")
                print("Dados residuais do pacote limpos")
                print("APK removido do emulador")
            except Exception as e:
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao limpar dados residuais: {e}", caminho_upload_pcap

            # ===============================================================================================

            #Transfere a captura de pacotes de rede para o computador local
            try:
                executar_comando_adb(f"-s {dispositivo} pull {caminho_remoto_pcap} {caminho_local_pcap}")
                print("Captura de pacotes de rede transferida para o computador local")
            except Exception as e:
                return False, dumpsys_bd, logcat_bd, arquivos_modificados, f"Erro ao transferir captura de pacotes de rede: {e}", caminho_upload_pcap

            # ===============================================================================================

        except Exception as e:
            # Remover o APK do dispositivo em caso de erro e retornar um dicionário vazio
            executar_comando_adb(f"-s {dispositivo} uninstall {nome_pacote}")
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_apk}")
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_pcap}")
            desconectar_adb(dispositivo)
            print("Ocorreu um erro durante a análise do pacote")
            return False, {}, {}, [], f"Ocorreu um erro durante a análise do pacote: {e}", caminho_upload_pcap

        # ===============================================================================================

        finally:
            # Desconecta do dispositivo
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_pcap}")
            executar_comando_adb(f"-s {dispositivo} shell rm {caminho_remoto_apk}")
            desconectar_adb(dispositivo)
            print("Conexão ADB encerrada")

        # ===============================================================================================
    else:
        return False, {}, {}, [], f"Não foi possivel fechar a conexão", caminho_upload_pcap  # Retorna as variáveis capturadas

    return True, dumpsys_bd, logcat_bd, arquivos_modificados, "", caminho_upload_pcap  # Retorna as variáveis capturadas

# ===============================================================================================
