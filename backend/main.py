import os
import re
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
    """Verifica se o pacote existe no registro oficial do PyPI."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    req = urllib.request.Request(url, headers={'User-Agent': 'VibeCheckAuditor/1.0'})
    try:
        with urllib.request.urlopen(req) as response:
            return response.status == 200
    except Exception:
        return False

def extrair_pacotes_requirements(caminho_arquivo: str) -> list[str]:
    """Extrai os nomes dos pacotes do requirements.txt."""
    pacotes = []
    if not os.path.exists(caminho_arquivo):
        return pacotes

    with open(caminho_arquivo, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                pkg = linha.split("==")[0].split(">=")[0].split("<=")[0].strip()
                if pkg:
                    pacotes.append(pkg)
    return pacotes

def escanear_codigo_python(diretorio: str) -> tuple[list[dict], int, int]:
    """Percorre os arquivos .py do projeto buscando vulnerabilidades e segredos expostos."""
    achados = []
    total_vulns = 0
    total_secrets = 0

    # Padrões para identificar segredos (API Keys, Tokens)
    padroes_secrets = [
        (r'sk-[a-zA-Z0-9]{32,}', "Chave de API OpenAI Exposta", "CRITICA"),
        (r'AKIA[0-9A-Z]{16}', "Chave de Acesso AWS Exposta", "CRITICA"),
        (r'ghp_[a-zA-Z0-9]{36}', "Personal Access Token do GitHub Exposto", "CRITICA"),
        (r'(?i)(password|senha|secret)\s*=\s*[\'"][^\'"]+[\'"]', "Senha/Segredo Hardcoded", "ALTA")
    ]

    # Padrões para identificar vulnerabilidades comuns de código gerado por IA
    padroes_vulns = [
        (r'\beval\(', "Uso do método eval()", "ALTA", "Execução arbitrária de código Python."),
        (r'\bexec\(', "Uso do método exec()", "ALTA", "Execução dinâmica de código sem validação."),
        (r'shell\s*=\s*True', "Subprocess com shell=True", "ALTA", "Risco de Injeção de Comandos de Sistema (Command Injection)."),
        (r'SELECT\s+.*\s+FROM\s+.*\+.*', "Possível SQL Injection", "ALTA", "Concatenação direta de variáveis em queries SQL.")
    ]

    for raiz, _, ficheiros in os.walk(diretorio):
        for ficheiro in ficheiros:
            if ficheiro.endswith(".py"):
                caminho_completo = os.path.join(raiz, ficheiro)
                rel_path = os.path.relpath(caminho_completo, diretorio)

                try:
                    with open(caminho_completo, "r", encoding="utf-8", errors="ignore") as f:
                        linhas = f.readlines()

                    for num_linha, linha in enumerate(linhas, start=1):
                        # Checagem de Secrets
                        for padrao, tipo, gravidade in padroes_secrets:
                            if re.search(padrao, linha):
                                total_secrets += 1
                                achados.append({
                                    "tipo": tipo,
                                    "gravidade": gravidade,
                                    "arquivo": rel_path,
                                    "linha": num_linha,
                                    "mensagem": "Credencial sensível detetada no código-fonte."
                                })

                        # Checagem de Vulnerabilidades
                        for padrao, tipo, gravidade, msg in padroes_vulns:
                            if re.search(padrao, linha):
                                total_vulns += 1
                                achados.append({
                                    "tipo": tipo,
                                    "gravidade": gravidade,
                                    "arquivo": rel_path,
                                    "linha": num_linha,
                                    "mensagem": msg
                                })

                except Exception:
                    continue

    return achados, total_vulns, total_secrets


@app.post("/api/v1/scan")
def realizar_scan(dados: ScanRequest):
    temp_dir = tempfile.mkdtemp()
    
    try:
        # 1. Clonar repositório
        Repo.clone_from(dados.repo_url, temp_dir, depth=1)
        
        # 2. Análise de pacotes (requirements.txt)
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
        achados_pacotes = []
        for pkg_fake in alucinados:
            achados_pacotes.append({
                "tipo": "Pacote Alucinado por IA",
                "gravidade": "CRITICA",
                "arquivo": "requirements.txt",
                "linha": 1,
                "mensagem": f"O pacote '{pkg_fake}' não existe no PyPI. Risco de Typosquatting/Dependency Confusion."
            })

        # 3. Análise dos arquivos de código (.py)
        achados_codigo, vulns, secrets = escanear_codigo_python(temp_dir)

        # Junta todos os achados
        todos_achados = achados_pacotes + achados_codigo

        # Cálculo do Score de Segurança
        deducoes = (qtd_alucinados * 25) + (secrets * 20) + (vulns * 15)
        score = max(100 - deducoes, 0)

        return {
            "repositorio": dados.repo_url,
            "status": "sucesso",
            "metricas": {
                "vulnerabilidades": vulns,
                "segredos_expostos": secrets,
                "pacotes_alucinados": qtd_alucinados,
                "pontuacao_seguranca": score
            },
            "achados_seguranca": todos_achados,
            "pacotes_testados": pacotes_testados
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao analisar repositório: {str(e)}")
    
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)