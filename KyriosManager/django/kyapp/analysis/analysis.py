import time
from dotenv import load_dotenv
from ..models import AnaliseAPK
from .utils import calcular_tempo, salvar_apk, excluir_apk
from .virustotal import vt_analise_estatica, formatar_orm_bd
from .urls_ky import analise_urls, whois_urls
from .permissions import leitura_manifesto_perms
from .infos import infos_apk, abis_apk
from .adb import gerenciador_adb
import zipfile

# Carrega variáveis de ambiente do arquivo .env
load_dotenv()

# ===============================================================================================

def analisar_arquivo(apk_file, user_id, nome_arquivo, extensao, flag_dinamica):
    """
    Analisa o arquivo APK fornecido, realizando uma análise estática com VirusTotal e AndroGuard, 
    além de uma análise dinâmica (opcional) em um emulador Android.

    Args:
        apk_file: Arquivo APK a ser analisado.
        user_id: ID do usuário que está solicitando a análise.
        nome_arquivo: Nome original do arquivo APK.
        extensao: Extensão do arquivo APK.
        flag_dinamica: Flag indicando se a análise deve incluir a análise dinâmica.

    Returns:
        Tuple: Status da operação (True/False), mensagem principal, e mensagem de análise dinâmica.
    """

    # Inicia a contagem do tempo de execução da função
    tempo_inicio = time.time()
    ocorreu_erro = False  # Flag para indicar se houve erro
    msg_erro = ""  # Mensagem de erro
    msg_info_dinamica = ""  # Mensagem informativa sobre a análise dinâmica

    # ===============================================================================================
    # LEITURA DO ARQUIVO APK

    try:
        # Lê os bytes do arquivo APK
        apk_bytes = apk_file.read()
    except Exception as e:
        return False, f"Erro ao ler o arquivo APK: {str(e)}"

    # ===============================================================================================
    # ANÁLISE ESTÁTICA: VirusTotal

    try:
        frmt_redesameacas, frmt_contextorede, frmt_classificacao, frmt_antivirus, hashs = vt_analise_estatica(apk_bytes, apk_file.name)
    except Exception as e:
        frmt_redesameacas, frmt_contextorede, frmt_classificacao, frmt_antivirus, hashs = formatar_orm_bd({}, {}, {}, {}, {})
        ocorreu_erro = True
        msg_erro = f"Erro na análise estática com VirusTotal: {str(e)}"

    # ===============================================================================================
    # SALVANDO APK 

    caminho_apk, hash_sha256 = salvar_apk(apk_file, apk_bytes)

    with zipfile.ZipFile(caminho_apk, 'r') as apk_zip:
        # Análise de URLs
        try:
            urls = analise_urls(apk_zip)
        except Exception as e:
            urls = []
            ocorreu_erro = True
            msg_erro = f"Erro na análise de URLs-1: {str(e)}"

        # Análise de ABIs
        try:
            abis = abis_apk(apk_zip)
        except Exception as e:
            abis = []
            ocorreu_erro = True
            msg_erro = f"Erro na análise das ABIs do APK: {str(e)}"
    
    # ===============================================================================================
    # LEITURA DE PERMISSÕES

    try:
        perms_detalhadas, perms_declaradas = leitura_manifesto_perms(caminho_apk)
    except Exception as e:
        perms_detalhadas, perms_declaradas = {}, {}
        ocorreu_erro = True
        msg_erro = f"Erro na leitura de permissões: {str(e)}"

    # ===============================================================================================
    # COLETA DE INFORMAÇÕES DETALHADAS DO APK

    try:
        nome_do_pacote, atividade_principal, todas_atividades, todos_servicos = infos_apk(caminho_apk)
    except Exception as e:
        nome_do_pacote, atividade_principal, todas_atividades, todos_servicos = '', '', [], []
        ocorreu_erro = True
        msg_erro = f"Erro ao obter informações detalhadas do APK: {str(e)}"

    # ===============================================================================================
    # ANÁLISE DE URLs

    try:
        info_urls = whois_urls(urls)
    except Exception as e:
        info_urls = []
        ocorreu_erro = True
        msg_erro = f"Erro na análise de URLs-2: {str(e)}"

    # ===============================================================================================

    # Calcula o tempo de download e envio
    tempo_download_envio = calcular_tempo(tempo_inicio, time.time())

    # ====================================================

    # Cria uma instância de AnaliseAPK no banco de dados
    analise_apk = AnaliseAPK.objects.create(
        usuario_id=user_id,
        nome=nome_arquivo,
        ext=extensao,
        status='Analisado' if not ocorreu_erro else 'Erro na análise',
        tempo=tempo_download_envio,
        estatica={
            'NomePacote': nome_do_pacote,
            'ABIS': abis,
            'Hashs': hashs,
            'urls': urls,
            'info_urls': info_urls,
            'perms_detalhadas': perms_detalhadas,
            'perms_declaradas': perms_declaradas,
            'atv_principal': atividade_principal,
            'todas_atv': todas_atividades,
            'todos_srv': todos_servicos,
        },
        virustotal={
            'AntivirusClassificacao': frmt_classificacao,
            'Antivirus': frmt_antivirus,
            'Redes': frmt_contextorede,
            'RedesClassificacao': frmt_redesameacas, 
        },

    )

    # Obtém o ID do registro criado
    apk_id = analise_apk.id_json
    
    # ===============================================================================================

    # Verificação de ABIS para análise dinâmica
    if flag_dinamica and ('x86' in abis or 'x86_64' in abis):

        # Inicializa a flag para arquitetura x86 e x86_64
        flag_x86_e_X86_64 = False
        if 'x86' in abis and 'x86_64' not in abis:
            flag_x86_e_X86_64 = True
        elif 'x86_64' in abis and 'x86' not in abis:
            flag_x86_e_X86_64 = False
        elif 'x86' in abis and 'x86_64' in abis:
            flag_x86_e_X86_64 = False

        # ===============================================================================================
        print("aq")
        # Chama o gerenciador ADB
        status, dumpsys_bd, logcat_bd, arquivos_modificados, mensagem_erro, caminho_upload_pcap = gerenciador_adb(
            flag_x86_e_X86_64, caminho_apk, hash_sha256, nome_do_pacote, apk_id
        )

        # ===============================================================================================

        if status:
            excluir_apk(caminho_apk)

            # ===============================================================================================
            print("a")
            # Atualiza o campo 'dinamica' e 'tempo' no banco de dados após a análise dinâmica
            tempo_final = calcular_tempo(tempo_inicio, time.time())
            AnaliseAPK.objects.filter(id_json=apk_id).update(
                dinamica={
                        'dumpsys': dumpsys_bd,
                        "logs": logcat_bd,
                        "arquivos": arquivos_modificados,
                        "upload_url": caminho_upload_pcap,
                        },
                tempo=tempo_final
            )

            msg_info_dinamica = "Análise dinâmica realizada com sucesso."

            # ===============================================================================================

        else:
            ocorreu_erro = True
            msg_erro = f"Erro durante a análise dinâmica: {mensagem_erro}"

    # ===============================================================================================

    elif flag_dinamica and ('armeabi' in abis or 'armeabi-v7a' in abis or 'arm64-v8a' in abis):
        msg_info_dinamica = "A análise dinâmica não está disponível para as arquiteturas do APK fornecido: armeabi, armeabi-v7a ou arm64-v8a."

    # ===============================================================================================

    else:
        msg_info_dinamica = "Análise dinâmica está desabilitada."

    # ===============================================================================================
    
    # Exclui o APK independente do resultado
    excluir_apk(caminho_apk)

    # ===============================================================================================

    # Retorna o resultado da análise
    if ocorreu_erro:
        return False, msg_erro, msg_info_dinamica
    else:
        return True, "Análise concluída com sucesso!", msg_info_dinamica


# ==================================================================================================================
    

