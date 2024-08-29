import os
import requests
from datetime import datetime
import time

def VT_api(file):
    #Url para requisicao da URL de upload
    url = "https://www.virustotal.com/api/v3/files/upload_url"

    #Header file com os dados do arquivo de analise
    files = { "file": ("teste", open(file, "rb"), "application/vnd.android.package-archive") }

    #Demais inforamcoes do header com a chame api sendo um variavel de ambiente
    headers = {
        "accept": "application/json",
        "x-apikey": os.environ.get("VT_API")  #Chave api variavel de ambiente com nome de VT_API
    }

    #Requisicao da URL de upload
    response = (requests.get(url, headers=headers)).json()

    #Upload do arquivos
    response = (requests.post(response['data'],files=files,headers=headers)).json()

    #As vezes a requisicao pode demorar um pouco pra ficar pronto
    time.sleep(5)
 
    #Requisicao da situacao da analise
    response = (requests.get(response['data']['links']['self'],headers=headers)).json()

    #Resultado da analise
    response = (requests.get(response['data']['links']['item'],headers=headers)).json()

    #Categorias atribuidas ao arquivo
    categoria_ameaca = response["data"]['attributes']['popular_threat_classification']['popular_threat_category']
    
    #Cassificacoes atribuidas ao arquivo
    classificacao_ameaca = response["data"]['attributes']["last_analysis_stats"]
    
    #Resultados de engines de antivirus
    antivirus_resultados = response["data"]['attributes']["last_analysis_results"]
    
    #Nivel de Ameaca para a rede
    rede_ameaca = response["data"]['attributes']["crowdsourced_ids_stats"]

    #Contexto de rede (IP,URLs,Hosts) cadastrado por IDS
    tam_res = len(response["data"]['attributes']["crowdsourced_ids_results"])
    contexto_rede = []
    for a in range(tam_res):
        if response["data"]['attributes']["crowdsourced_ids_results"][a]["alert_context"] in contexto_rede:
            pass
        else:
            contexto_rede.append(response["data"]['attributes']["crowdsourced_ids_results"][a]["alert_context"])
    
    #Primeiro avistamento
    primeiro_avistamento = (datetime.fromtimestamp(response["data"]['attributes']["first_submission_date"])).strftime('%Y-%m-%d %H:%M:%S')

    return {'categoria_ameaca':categoria_ameaca,'classificacao_ameaca':classificacao_ameaca,'antivirus_resultados':antivirus_resultados,'rede_ameaca':rede_ameaca,'contexto_rede':contexto_rede, 'primeiro_avistamento':primeiro_avistamento }
