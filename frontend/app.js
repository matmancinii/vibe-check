async function executarScan() {
    const repoUrl = document.getElementById('repoUrl').value;
    const btnScan = document.getElementById('btnScan');
    const resultados = document.getElementById('resultados');
    const listaAchados = document.getElementById('listaAchados');

    if (!repoUrl) {
        alert("Por favor, digite uma URL de repositório!");
        return;
    }

    // Feedback visual de carregamento
    btnScan.innerText = "Analisando...";
    btnScan.disabled = true;

    try {
        // Chamada assíncrona (fetch) para a API Python
        const response = await fetch('http://127.0.0.1:8000/api/v1/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repo_url: repoUrl })
        });

        if (!response.ok) {
            throw new Error(`Erro na requisição: ${response.statusText}`);
        }

        const data = await response.json();

        // Preencher os cards de métricas
        document.getElementById('metricVulns').innerText = data.metricas.vulnerabilidades;
        document.getElementById('metricSecrets').innerText = data.metricas.segredos_expostos;
        document.getElementById('metricPackages').innerText = data.metricas.pacotes_alucinados;
        document.getElementById('metricScore').innerText = `${data.metricas.pontuacao_seguranca}/100`;

        // Limpar a lista de achados anterior
        listaAchados.innerHTML = "";

        if (data.achados_seguranca.length === 0) {
            listaAchados.innerHTML = `
                <div class="bg-emerald-950/40 p-4 rounded-lg border border-emerald-500/30 text-emerald-400 text-sm font-semibold text-center">
                    🎉 Nenhum problema de segurança ou pacote alucinado foi encontrado neste repositório!
                </div>
            `;
        } else {
            // Preencher com a lista de alertas e botão da IA
            data.achados_seguranca.forEach((item, index) => {
                const idElementoIA = `ia-res-${index}`;
                const card = document.createElement('div');
                card.className = "bg-slate-900 p-4 rounded-lg border border-slate-700 space-y-3";
                
                card.innerHTML = `
                    <div class="flex justify-between items-start gap-4">
                        <div>
                            <span class="text-xs px-2 py-1 bg-rose-500/20 text-rose-400 font-bold rounded mr-2">${item.gravidade}</span>
                            <strong class="text-slate-200">${item.tipo}</strong>
                            <p class="text-sm text-slate-400 mt-1">${item.mensagem}</p>
                            <code class="text-xs text-indigo-300">${item.arquivo}:${item.linha}</code>
                        </div>
                        <button onclick="pedirAjudaIA('${escapeHtml(item.tipo)}', '${escapeHtml(item.mensagem)}', '${escapeHtml(item.arquivo)}', ${item.linha}, '${idElementoIA}')" 
                                class="bg-purple-600 hover:bg-purple-500 text-xs font-semibold px-3 py-2 rounded text-white transition-colors flex items-center gap-1 shrink-0">
                            🤖 Corrigir com IA
                        </button>
                    </div>
                    <div id="${idElementoIA}" class="hidden bg-slate-950 p-3 rounded text-xs font-mono text-purple-200 border border-purple-500/30 whitespace-pre-wrap"></div>
                `;
                listaAchados.appendChild(card);
            });
        }

        // Exibir a seção de resultados na tela
        resultados.classList.remove('hidden');

    } catch (error) {
        alert("Erro ao conectar com o servidor backend!");
        console.error(error);
    } finally {
        btnScan.innerText = "Iniciar Análise";
        btnScan.disabled = false;
    }
}

// Função para evitar erros de sintaxe ao passar textos com aspas no HTML
function escapeHtml(texto) {
    if (!texto) return '';
    return texto
        .replace(/'/g, "\\'")
        .replace(/"/g, '&quot;');
}

// Função assíncrona para consultar o endpoint da NVIDIA NIM
async function pedirAjudaIA(tipo, mensagem, arquivo, linha, idElemento) {
    const painelResposta = document.getElementById(idElemento);
    painelResposta.classList.remove('hidden');
    painelResposta.innerText = "⏳ Consultando NVIDIA NIM...";

    try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/explain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tipo: tipo,
                mensagem: mensagem,
                arquivo: arquivo,
                linha: linha
            })
        });

        if (!response.ok) {
            throw new Error(`Erro no servidor: ${response.statusText}`);
        }

        const data = await response.json();
        painelResposta.innerText = data.resposta;
    } catch (error) {
        painelResposta.innerText = "❌ Erro ao obter resposta da IA. Verifique se o servidor backend está ativo e com a chave no .env.";
        console.error(error);
    }
}

let ultimoResultadoScan = null;

// Salva o resultado no window para poder exportar no PDF
// (Adicione esta linha dentro do executarScan(), logo após const data = await response.json();)
ultimoResultadoScan = data;

async function baixarRelatorioPDF() {
    if (!ultimoResultadoScan) {
        alert("Realize uma análise antes de exportar o relatório!");
        return;
    }

    const response = await fetch('http://127.0.0.1:8000/api/v1/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ultimoResultadoScan)
    });

    const htmlContent = await response.text();
    const win = window.open('', '_blank');
    win.document.write(htmlContent);
    win.document.close();
}