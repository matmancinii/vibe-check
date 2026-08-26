import os
import re
import shutil
import tempfile
import urllib.request
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from pydantic import BaseModel
from git import Repo

# Carrega a chave de API do arquivo .env
load_dotenv()

app = FastAPI(title="Vibe Security Auditor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos para validação das requisições
class ScanRequest(BaseModel):
    repo_url: str

class ExplainRequest(BaseModel):
    tipo: str
    mensagem: str
    arquivo: str
    linha: int

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

    padroes_secrets = [
        (r'sk-[a-zA-Z0-9]{32,}', "Chave de API OpenAI Exposta", "CRITICA"),
        (r'AKIA[0-9A-Z]{16}', "Chave de Acesso AWS Exposta", "CRITICA"),
        (r'ghp_[a-zA-Z0-9]{36}', "Personal Access Token do GitHub Exposto", "CRITICA"),
        (r'(?i)(password|senha|secret)\s*=\s*[\'"][^\'"]+[\'"]', "Senha/Segredo Hardcoded", "ALTA")
    ]

    padroes_vulns = [
        (r'\beval\(', "Uso do método eval()", "ALTA", "Execução arbitrária de código Python."),
        (r'\bexec\(', "Uso do método exec()", "ALTA", "Execução dinâmica de código sem validação."),
        (r'shell\s*=\s*True', "Subprocess com shell=True", "ALTA", "Risco de Injeção de Comandos de Sistema (Command Injection)."),
        (r'SELECT\s+.*\s+FROM\s+.*\+.*', "Possível SQL Injection", "ALTA", "Concatenação direta de variáveis em queries SQL.")
    ]

    for raiz, _, ficheiros in os.walk(diretorio):
        # Ignora a própria pasta backend e ambientes virtuais para evitar falsos positivos
        partes_caminho = raiz.split(os.sep)
        if "backend" in partes_caminho or ".venv" in partes_caminho or "venv" in partes_caminho:
            continue

        for ficheiro in ficheiros:
            if ficheiro.endswith(".py"):
                caminho_completo = os.path.join(raiz, ficheiro)
                rel_path = os.path.relpath(caminho_completo, diretorio)

                try:
                    with open(caminho_completo, "r", encoding="utf-8", errors="ignore") as f:
                        linhas = f.readlines()

                    for num_linha, linha in enumerate(linhas, start=1):
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
        
        # 2. Análise de pacotes
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

        # 3. Análise do código Python
        achados_codigo, vulns, secrets = escanear_codigo_python(temp_dir)
        todos_achados = achados_pacotes + achados_codigo

        # Cálculo de Score
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


@app.post("/api/v1/explain")
def explicar_com_ia(dados: ExplainRequest):
    api_key = os.getenv("NVIDIA_API_KEY")
    
    if not api_key:
        return {"resposta": "⚠️ Chave NVIDIA_API_KEY não encontrada no arquivo .env."}

    try:
        client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=api_key
        )

        prompt = f"""
Você é um especialista sênior em segurança de software.
Foi encontrada a seguinte vulnerabilidade no projeto:

- Tipo: {dados.tipo}
- Arquivo: {dados.arquivo} (Linha {dados.linha})
- Detalhes: {dados.mensagem}

Responda em Português de forma clara e objetiva:
1. Explicação curta do risco (máximo 2 frases).
2. Exemplo de código seguro para corrigir o problema.
"""

        completion = client.chat.completions.create(
            model="meta/llama-3.2-90b-vision-instruct",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=400
        )

        return {"resposta": completion.choices[0].message.content}

    except Exception as e:
        return {"resposta": f"Erro ao consultar NVIDIA NIM: {str(e)}"}

from fastapi.responses import HTMLResponse

@app.post("/api/v1/report", response_class=HTMLResponse)
def gerar_relatorio_html(dados: dict):
    """Gera um relatório formatado em HTML/PDF pronto para impressão ou download."""
    metricas = dados.get("metricas", {})
    achados = dados.get("achados_seguranca", [])
    repo = dados.get("repositorio", "N/A")

    linhas_achados = ""
    for item in achados:
        linhas_achados += f"""
        <tr style="border-bottom: 1px solid #ddd;">
            <td style="padding: 8px; font-weight: bold; color: #e11d48;">{item.get('gravidade')}</td>
            <td style="padding: 8px;">{item.get('tipo')}</td>
            <td style="padding: 8px; font-family: monospace;">{item.get('arquivo')}:{item.get('linha')}</td>
            <td style="padding: 8px;">{item.get('mensagem')}</td>
        </tr>
        """

    if not linhas_achados:
        linhas_achados = '<tr><td colspan="4" style="text-align:center; padding: 15px; color: #059669;">Nenhuma vulnerabilidade encontrada. Repositório Seguro!</td></tr>'

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Relatório Executivo de Segurança</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; color: #333; }}
            h1 {{ color: #4f46e5; border-bottom: 2px solid #4f46e5; padding-bottom: 5px; }}
            .metrics {{ display: flex; gap: 15px; margin: 20px 0; }}
            .card {{ background: #f3f4f6; padding: 15px; border-radius: 8px; flex: 1; text-align: center; }}
            .card h3 {{ margin: 0; font-size: 24px; color: #1f2937; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #1e293b; color: white; padding: 10px; text-align: left; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Relatório Executivo de Auditoria de Segurança</h1>
        <p><strong>Repositório Auditado:</strong> {repo}</p>
        
        <div class="metrics">
            <div class="card"><p>Score de Segurança</p><h3>{metricas.get('pontuacao_seguranca', 0)}/100</h3></div>
            <div class="card"><p>Vulnerabilidades</p><h3>{metricas.get('vulnerabilidades', 0)}</h3></div>
            <div class="card"><p>Secrets Expostos</p><h3>{metricas.get('segredos_expostos', 0)}</h3></div>
            <div class="card"><p>Pacotes Alucinados</p><h3>{metricas.get('pacotes_alucinados', 0)}</h3></div>
        </div>

        <h2>Detalhamento dos Achados</h2>
        <table>
            <thead>
                <tr>
                    <th>Gravidade</th>
                    <th>Tipo</th>
                    <th>Localização</th>
                    <th>Descrição</th>
                </tr>
            </thead>
            <tbody>
                {linhas_achados}
            </tbody>
        </table>
        <script>window.onload = function() {{ window.print(); }}</script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)