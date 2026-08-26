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

        const data = await response.json();

        // Preencher métricas
        document.getElementById('metricVulns').innerText = data.metricas.vulnerabilidades;
        document.getElementById('metricSecrets').innerText = data.metricas.segredos_expostos;
        document.getElementById('metricPackages').innerText = data.metricas.pacotes_alucinados;
        document.getElementById('metricScore').innerText = `${data.metricas.pontuacao_seguranca}/100`;

        // Preencher lista de achados
        listaAchados.innerHTML = "";
        data.achados_seguranca.forEach(item => {
            const card = document.createElement('div');
            card.className = "bg-slate-900 p-4 rounded-lg border border-slate-700 flex justify-between items-center";
            card.innerHTML = `
                <div>
                    <span class="text-xs px-2 py-1 bg-rose-500/20 text-rose-400 font-bold rounded mr-2">${item.gravidade}</span>
                    <strong class="text-slate-200">${item.tipo}</strong>
                    <p class="text-sm text-slate-400 mt-1">${item.mensagem}</p>
                    <code class="text-xs text-indigo-300">${item.arquivo}:${item.linha}</code>
                </div>
            `;
            listaAchados.appendChild(card);
        });

        // Exibir a seção de resultados
        resultados.classList.remove('hidden');

    } catch (error) {
        alert("Erro ao conectar com o servidor backend!");
        console.error(error);
    } finally {
        btnScan.innerText = "Iniciar Análise";
        btnScan.disabled = false;
    }
}