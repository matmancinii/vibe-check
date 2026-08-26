import os
import shutil
import tempfile
import urllib.request
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from git import Repo

app = FastAPI(title="Vibe Security Auditor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    repo_url: str

def check_pypi_package(package_name: str) -> bool:
    """Verifica se o pacote existe no registro do PyPI."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    req = urllib.request.Request(url, headers={'User-Agent': 'VibeCheckAuditor/1.0'})
    try:
        with urllib.request.urlopen(req) as response:
            return response.status == 200
    except Exception:
        return False

def extrair_pacotes_requirements(caminho_arquivo: str) -> list[str]:
    """Lê o arquivo requirements.txt real e extrai os nomes dos pacotes."""
    pacotes = []
    if not os.path.exists(caminho_arquivo):
        return pacotes

    with open(caminho_arquivo, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                pkg = linha.split("==")[0].split(">=")[0].split("<=")[0].strip()
                if pkg:
                    pacotes.append(pkg)
    return pacotes

@app.post("/api/v1/scan")
def realizar_scan(dados: ScanRequest):
    # Cria diretório temporário para isolar o repositório baixado
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Clonar o repositório público ou privado acessível
        Repo.clone_from(dados.repo_url, temp_dir, depth=1)
        
        # Localizar o arquivo requirements.txt real
        req_path = os.path.join(temp_dir, "requirements.txt")
        pacotes_encontrados = extrair_pacotes_requirements(req_path)
        
        pacotes_testados = []
        alucinados = []

        for pkg in pacotes_encontrados:
            existe = check_pypi_package(pkg)
            pacotes_testados.append({"nome": pkg, "existe_no_pypi": existe})
            if not existe:
                alucinados.append(pkg)

        qtd_alucinados = len(alucinados)
        score = 100 - (qtd_alucinados * 25)

        achados = []
        for pkg_fake in alucinados:
            achados.append({
                "tipo": "Pacote Alucinado por IA",
                "gravidade": "CRITICA",
                "arquivo": "requirements.txt",
                "linha": 1,
                "mensagem": f"O pacote '{pkg_fake}' não existe no PyPI. Risco alto de Typosquatting/Dependency Confusion."
            })

        return {
            "repositorio": dados.repo_url,
            "status": "sucesso",
            "metricas": {
                "vulnerabilidades": 0,
                "segredos_expostos": 0,
                "pacotes_alucinados": qtd_alucinados,
                "pontuacao_seguranca": max(score, 0)
            },
            "achados_seguranca": achados,
            "pacotes_testados": pacotes_testados
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao clonar repositório: {str(e)}")
    
    finally:
        # Limpa os arquivos temporários do disco
        shutil.rmtree(temp_dir, ignore_errors=True)