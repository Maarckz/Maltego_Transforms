import sys
import subprocess
import json
from maltego_trx.maltego import MaltegoTransform

# 1. Pega o domínio que você clicou lá no Maltego
dominio_alvo = sys.argv[1]

# 2. Inicia o "tradutor" do Maltego
transform = MaltegoTransform()

try:
    # 3. Executa o SEU script original e captura a saída dele
    comando = ['/usr/bin/python3', '/home/maarckz/Documentos/Python/INGEST_CTI/integrations/dnsdumpster.py', dominio_alvo]
    resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
    
    # 4. Transforma o texto (JSON) em um dicionário Python
    dados = json.loads(resultado.stdout)
    
    # 5. Varre os "a_records" e cria uma bolinha (Entidade) para cada subdomínio
    if "a_records" in dados:
        for registro in dados["a_records"]:
            subdominio = registro.get("host")
            ip = registro.get("ip")
            
            # Cria a entidade do tipo DNS Name (Subdomínio)
            ent = transform.addEntity("maltego.DNSName", subdominio)
            
            # (Opcional) Adiciona o IP como uma propriedade oculta na entidade
            if ip:
                ent.addProperty("ipv4", "IP Address", "strict", ip)

except Exception as e:
    # Se der erro, manda uma mensagem de erro vermelha pro Maltego
    transform.addUIMessage(f"Erro ao processar: {str(e)}", messageType="PartialError")

# 6. Imprime o resultado final no formato XML que o Maltego exige!
print(transform.returnOutput())
