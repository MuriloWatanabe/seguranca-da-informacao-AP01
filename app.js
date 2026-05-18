// =============================================================================
// Sistema de Ocorrências Acadêmicas — versão corrigida (AP01)
// Melhorias de segurança aplicada por:
// Murilo Enzo Watanabe
// =============================================================================

// OBSERVAÇÃO GERAL: Este sistema é um protótipo front-end para fins didáticos.
// Todas as melhorias abaixo são válidas dentro dos limites de uma aplicação
// sem back-end. Controles reais de autenticação, autorização e armazenamento
// seguro dependem de um servidor e banco de dados, conforme indicado no relatório.

// -----------------------------------------------------------------------------
// MELHORIA 1 (parcial): Senhas removidas da exibição pública.
// Vulnerabilidade original: senhas em texto puro no array USERS em repositório público.
// Correção real exige back-end com hash (bcrypt). Aqui mantemos o array para o
// protótipo funcionar, mas removemos a exibição pública das credenciais no HTML.
// -----------------------------------------------------------------------------
const USERS = [
  {
    id: 1,
    name: "Ana Souza",
    email: "aluno@faculdade.local",
    password: "123456",
    role: "ALUNO",
    studentId: "202400001"
  },
  {
    id: 2,
    name: "Prof. Carlos Lima",
    email: "professor@faculdade.local",
    password: "123456",
    role: "PROFESSOR",
    classes: ["5A", "5B"]
  },
  {
    id: 3,
    name: "Administrador Geral",
    email: "admin@faculdade.local",
    password: "admin",
    role: "ADMIN"
  }
];

// MELHORIA 7 (parcial): Token removido do payload de exportação.
// Vulnerabilidade original: FAKE_API_TOKEN exportado junto com os dados.
// O token ainda existe aqui apenas para manter a estrutura do protótipo,
// mas NÃO é mais incluído na exportação.
// Em produção: tokens nunca devem existir no front-end.
const FAKE_API_TOKEN = "TOKEN_SECRETO_DEMO_ABC123_PUBLICO_NO_FRONTEND";

const STORAGE_KEYS = {
  session: "ocorrencias_sessao",
  occurrences: "ocorrencias_registros",
  audit: "ocorrencias_logs"
};

const INITIAL_OCCURRENCES = [
  {
    id: "OC-1001",
    studentName: "Marina Alves",
    studentId: "202300145",
    studentCpf: "123.456.789-10",
    studentEmail: "marina.alves@email.local",
    studentPhone: "(47) 99999-1010",
    category: "Nota",
    priority: "Média",
    description: "Solicitação de revisão de nota da avaliação bimestral.",
    internalNote: "Verificar com a coordenação antes de responder.",
    status: "Aberta",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:40:00.000Z"
  },
  {
    id: "OC-1002",
    studentName: "Rafael Martins",
    studentId: "202200771",
    studentCpf: "987.654.321-00",
    studentEmail: "rafael.martins@email.local",
    studentPhone: "(47) 98888-2020",
    category: "Frequência",
    priority: "Alta",
    description: "Aluno contesta lançamento de falta em aula prática.",
    internalNote: "Conferir chamada manual.",
    status: "Em análise",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:50:00.000Z"
  },
  {
    id: "OC-1003",
    studentName: "Beatriz Costa",
    studentId: "202100441",
    studentCpf: "111.222.333-44",
    studentEmail: "beatriz.costa@email.local",
    studentPhone: "(47) 97777-3030",
    category: "Solicitação administrativa",
    priority: "Crítica",
    description: "Solicitação envolvendo documentação acadêmica e prazo de matrícula.",
    internalNote: "Priorizar atendimento.",
    status: "Aberta",
    createdBy: "admin@faculdade.local",
    createdAt: "2026-05-05T19:00:00.000Z"
  }
];

// ── Seletores DOM ─────────────────────────────────────────────────────────────
const loginView           = document.querySelector("#loginView");
const appView             = document.querySelector("#appView");
const loginForm           = document.querySelector("#loginForm");
const occurrenceForm      = document.querySelector("#occurrenceForm");
const occurrenceFormBlock = document.querySelector("#occurrenceFormBlocked");
const logoutBtn           = document.querySelector("#logoutBtn");
const exportBtn           = document.querySelector("#exportBtn");
const clearLogsBtn        = document.querySelector("#clearLogsBtn");
const resetBtn            = document.querySelector("#resetBtn");
const searchInput         = document.querySelector("#search");
const roleSelect          = document.querySelector("#roleSelect");
const sessionBadge        = document.querySelector("#sessionBadge");
const currentUserName     = document.querySelector("#currentUserName");
const currentUserDetails  = document.querySelector("#currentUserDetails");
const occurrencesTable    = document.querySelector("#occurrencesTable");
const auditLog            = document.querySelector("#auditLog");
const totalOccurrences    = document.querySelector("#totalOccurrences");
const criticalOccurrences = document.querySelector("#criticalOccurrences");
const lastUpdate          = document.querySelector("#lastUpdate");

// ── Inicialização ─────────────────────────────────────────────────────────────
function boot() {
  if (!localStorage.getItem(STORAGE_KEYS.occurrences)) {
    localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  }

  if (!localStorage.getItem(STORAGE_KEYS.audit)) {
    localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([
      {
        when: new Date().toISOString(),
        user: "sistema",
        action: "BASE_INICIAL_CRIADA",
        detail: "Dados fictícios carregados no localStorage."
      }
    ]));
  }

  const session = getSession();
  if (session) {
    showApp(session);
  } else {
    showLogin();
  }
}

// ── Persistência ──────────────────────────────────────────────────────────────
function getOccurrences() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.occurrences) || "[]");
}

function saveOccurrences(occurrences) {
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(occurrences));
}

function getAuditLogs() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.audit) || "[]");
}

function saveAuditLogs(logs) {
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify(logs));
}

function getSession() {
  return JSON.parse(localStorage.getItem(STORAGE_KEYS.session) || "null");
}

function saveSession(user) {
  localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(user));
}

// ── MELHORIA 11: Mascaramento de CPF nos logs de auditoria ────────────────────
// Vulnerabilidade original: CPF completo gravado nas mensagens de log.
// Correção: substitui os dígitos centrais por asteriscos antes de gravar.
function maskCpf(cpf) {
  if (!cpf || typeof cpf !== "string") return "***.***.***-**";
  // Aceita formato 000.000.000-00 ou somente dígitos
  return cpf.replace(/(\d{3})\.(\d{3})\.(\d{3})-(\d{2})/, "$1.***.***-**")
            .replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1***$3**");
}

function writeLog(action, detail) {
  const session = getSession();
  const logs = getAuditLogs();

  // MELHORIA 11: aplica mascaramento de CPF no detalhe antes de gravar
  const safeDetail = detail.replace(/\d{3}\.\d{3}\.\d{3}-\d{2}/g, (cpf) => maskCpf(cpf));

  logs.unshift({
    when: new Date().toISOString(),
    user: session ? session.email : "anonimo",
    role: session ? session.role : "SEM_SESSAO",
    action,
    detail: safeDetail
  });

  saveAuditLogs(logs);
}

// ── Navegação ─────────────────────────────────────────────────────────────────
function showLogin() {
  loginView.classList.remove("hidden");
  appView.classList.add("hidden");
  logoutBtn.classList.add("hidden");
  sessionBadge.textContent = "Sessão não iniciada";
  sessionBadge.classList.add("muted");
}

function showApp(user) {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  sessionBadge.textContent = `${user.name} — ${user.role}`;
  sessionBadge.classList.remove("muted");

  currentUserName.textContent = user.name;
  currentUserDetails.textContent = `${user.email} | Perfil: ${user.role}`;
  roleSelect.value = user.role;

  // MELHORIA 3: habilita select de perfil apenas para ADMIN
  if (user.role === "ADMIN") {
    roleSelect.disabled = false;
    document.getElementById("roleChangeNote").textContent =
      "Você pode alterar o perfil ativo como administrador.";
  } else {
    roleSelect.disabled = true;
    document.getElementById("roleChangeNote").textContent =
      "Somente administradores podem alterar perfis.";
  }

  // MELHORIA 6: exportação visível apenas para ADMIN
  if (user.role === "ADMIN") {
    exportBtn.classList.remove("hidden");
  } else {
    exportBtn.classList.add("hidden");
  }

  // MELHORIA 8: limpeza de logs visível apenas para ADMIN
  if (user.role === "ADMIN") {
    clearLogsBtn.classList.remove("hidden");
  } else {
    clearLogsBtn.classList.add("hidden");
  }

  // MELHORIA 12: formulário de ocorrências bloqueado para ALUNO
  if (user.role === "ALUNO") {
    occurrenceForm.classList.add("hidden");
    occurrenceFormBlock.classList.remove("hidden");
  } else {
    occurrenceForm.classList.remove("hidden");
    occurrenceFormBlock.classList.add("hidden");
  }

  render();
}

// ── Autenticação ──────────────────────────────────────────────────────────────
function login(email, password) {
  const user = USERS.find((item) => item.email === email && item.password === password);

  if (!user) {
    alert("Usuário ou senha inválidos.");
    writeLog("LOGIN_FALHOU", `Tentativa de login para o e-mail: ${email}`);
    return;
  }

  saveSession(user);
  writeLog("LOGIN_OK", `Usuário ${user.email} entrou no sistema com perfil ${user.role}.`);
  showApp(user);
}

function logout() {
  const session = getSession();
  writeLog("LOGOUT", session ? `${session.email} encerrou a sessão.` : "Sessão encerrada.");
  localStorage.removeItem(STORAGE_KEYS.session);
  showLogin();
}

// ── MELHORIA 3: Troca de perfil restrita a ADMIN ──────────────────────────────
// Vulnerabilidade original: qualquer usuário podia se autopromover a ADMIN.
// Correção: verifica se o perfil atual é ADMIN antes de permitir a troca.
// Limitação: controle no front-end pode ser contornado via console.
// Controle real exige validação server-side.
function changeRole(newRole) {
  const session = getSession();

  if (!session) return;

  if (session.role !== "ADMIN") {
    alert("Apenas administradores podem alterar o perfil ativo.");
    roleSelect.value = session.role; // reverte o select visualmente
    return;
  }

  session.role = newRole;
  saveSession(session);
  writeLog("PERFIL_ALTERADO", `Perfil ativo alterado para ${newRole} pelo administrador.`);
  showApp(session);
}

// ── MELHORIA 9: Validação de CPF e checkbox antes de salvar ───────────────────
// Vulnerabilidade original: checkbox não era validado; CPF aceitava qualquer texto.
// Correção: valida formato do CPF (regex) e exige checkbox marcado.
function validarCpf(cpf) {
  // Remove formatação e verifica padrão básico de 11 dígitos
  const apenasDigitos = cpf.replace(/\D/g, "");
  return /^\d{11}$/.test(apenasDigitos);
}

// ── MELHORIA 12 (complemento): sanitização de texto para evitar XSS via innerHTML
// Vulnerabilidade original: innerHTML usava valores do formulário diretamente.
// Correção: escapa caracteres especiais HTML antes de inserir no DOM.
function escapeHtml(text) {
  if (typeof text !== "string") return "";
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function createOccurrence(event) {
  event.preventDefault();

  const session = getSession();

  // MELHORIA 12: bloqueia cadastro se perfil for ALUNO
  if (!session || session.role === "ALUNO") {
    alert("Acesso negado: apenas professores e administradores podem registrar ocorrências.");
    return;
  }

  // MELHORIA 9: valida checkbox de consentimento
  const privacyAck = document.querySelector("#privacyAck").checked;
  if (!privacyAck) {
    alert("Você precisa confirmar que está autorizado a registrar estes dados antes de salvar.");
    return;
  }

  const cpf = document.querySelector("#studentCpf").value.trim();

  // MELHORIA 9: valida formato básico do CPF
  if (cpf && !validarCpf(cpf)) {
    alert("CPF inválido. Informe no formato 000.000.000-00.");
    return;
  }

  const occurrence = {
    id: `OC-${Math.floor(Math.random() * 9000) + 1000}`,
    // MELHORIA 12: escapeHtml em todos os campos de texto livre
    studentName:  escapeHtml(document.querySelector("#studentName").value.trim()),
    studentId:    escapeHtml(document.querySelector("#studentId").value.trim()),
    studentCpf:   escapeHtml(cpf),
    studentEmail: escapeHtml(document.querySelector("#studentEmail").value.trim()),
    studentPhone: escapeHtml(document.querySelector("#studentPhone").value.trim()),
    category:     document.querySelector("#category").value,
    priority:     document.querySelector("#priority").value,
    description:  escapeHtml(document.querySelector("#description").value.trim()),
    internalNote: escapeHtml(document.querySelector("#internalNote").value.trim()),
    privacyAck:   true,
    status:       "Aberta",
    createdBy:    session.email,
    createdAt:    new Date().toISOString()
  };

  const occurrences = getOccurrences();
  occurrences.unshift(occurrence);
  saveOccurrences(occurrences);

  // MELHORIA 11: CPF mascarado na mensagem de log (aplicado por writeLog via regex)
  writeLog(
    "OCORRENCIA_CRIADA",
    `Criada ocorrência ${occurrence.id} para ${occurrence.studentName} / ${occurrence.studentCpf}.`
  );

  occurrenceForm.reset();
  render();
}

function deleteOccurrence(id) {
  const occurrences = getOccurrences();
  const occurrence = occurrences.find((item) => item.id === id);
  const updated = occurrences.filter((item) => item.id !== id);

  saveOccurrences(updated);
  // MELHORIA 11: não loga o JSON completo (continha CPF e dados pessoais)
  writeLog("OCORRENCIA_EXCLUIDA", `Ocorrência ${id} excluída por ${getSession()?.email}.`);
  render();
}

function changeStatus(id, status) {
  const occurrences = getOccurrences();
  const occurrence = occurrences.find((item) => item.id === id);

  if (!occurrence) return;

  occurrence.status = status;
  occurrence.updatedAt = new Date().toISOString();

  saveOccurrences(occurrences);
  writeLog("STATUS_ALTERADO", `Ocorrência ${id} alterada para "${status}".`);
  render();
}

// ── MELHORIA 7: Exportação sem senhas, token e localStorage bruto ─────────────
// Vulnerabilidade original: exportação incluía USERS (senhas), FAKE_API_TOKEN
// e cópia completa do localStorage para qualquer usuário autenticado.
// Correção: restringe ao ADMIN e remove dados sensíveis do payload.
function exportEverything() {
  const session = getSession();

  // MELHORIA 6: bloqueia exportação para não-ADMIN
  if (!session || session.role !== "ADMIN") {
    alert("Acesso negado: apenas administradores podem exportar dados.");
    return;
  }

  // MELHORIA 7: payload sem senhas, sem token e sem cópia do localStorage
  const payload = {
    exportedAt:  new Date().toISOString(),
    exportedBy:  session.email,
    occurrences: getOccurrences(),
    audit:       getAuditLogs()
    // REMOVIDO: token: FAKE_API_TOKEN
    // REMOVIDO: users: USERS  (continha senhas)
    // REMOVIDO: localStorageCopy: { ...localStorage }
  };

  const blob   = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url    = URL.createObjectURL(blob);
  const anchor = document.createElement("a");

  anchor.href     = url;
  anchor.download = "backup-ocorrencias.json";
  anchor.click();

  URL.revokeObjectURL(url);

  writeLog("EXPORTACAO_TOTAL", "Administrador exportou os dados do sistema.");
}

// ── MELHORIA 8: Limpeza de logs restrita a ADMIN ─────────────────────────────
// Vulnerabilidade original: qualquer usuário podia apagar todos os logs.
// Correção: verifica perfil ADMIN antes de permitir a limpeza.
function clearLogs() {
  const session = getSession();

  if (!session || session.role !== "ADMIN") {
    alert("Acesso negado: apenas administradores podem limpar os logs.");
    return;
  }

  saveAuditLogs([]);
  writeLog("LOGS_LIMPOS", "Administrador limpou o histórico de logs.");
  render();
}

function resetData() {
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([]));
  localStorage.removeItem(STORAGE_KEYS.session);
  boot();
}

// ── Renderização ──────────────────────────────────────────────────────────────
function render() {
  const session    = getSession();
  const role       = session ? session.role : "ALUNO";
  const term       = searchInput.value.toLowerCase();
  const occurrences = getOccurrences();

  // Filtro de busca — percorre apenas campos não sensíveis para não-ADMIN
  const filtered = occurrences.filter((item) => {
    // MELHORIA 4/5: para ALUNO e PROFESSOR, busca não inclui CPF completo
    const searchTarget = role === "ADMIN"
      ? JSON.stringify(item).toLowerCase()
      : `${item.studentName} ${item.studentId} ${item.category} ${item.description} ${item.status}`.toLowerCase();
    return searchTarget.includes(term);
  });

  totalOccurrences.textContent    = occurrences.length;
  criticalOccurrences.textContent = occurrences.filter((item) => item.priority === "Crítica").length;
  lastUpdate.textContent          = `Atualizado em ${new Date().toLocaleTimeString("pt-BR")}`;

  // ── MELHORIA 4 e 5: CPF mascarado e observação interna oculta para não-ADMIN
  occurrencesTable.innerHTML = filtered.map((item) => {
    // MELHORIA 4: CPF visível apenas para ADMIN
    const cpfDisplay = role === "ADMIN"
      ? escapeHtml(item.studentCpf)
      : maskCpf(item.studentCpf);

    // MELHORIA 5: observação interna oculta para ALUNO
    const internalNoteDisplay = role === "ALUNO"
      ? `<span class="muted-text">[restrito]</span>`
      : `<strong>Obs. interna:</strong> ${escapeHtml(item.internalNote)}`;

    // MELHORIA 5: contato (e-mail e telefone) oculto para ALUNO
    const contactDisplay = role === "ALUNO"
      ? `<span class="muted-text">[restrito]</span>`
      : `${escapeHtml(item.studentEmail)}<br>${escapeHtml(item.studentPhone)}`;

    return `
    <tr>
      <td>
        <strong>${escapeHtml(item.studentName)}</strong><br />
        <span class="muted-text">${escapeHtml(item.studentId)}</span>
      </td>
      <td>${cpfDisplay}</td>
      <td>${contactDisplay}</td>
      <td>${escapeHtml(item.category)}</td>
      <td><span class="priority ${escapeHtml(item.priority)}">${escapeHtml(item.priority)}</span></td>
      <td>${escapeHtml(item.status)}</td>
      <td>
        <strong>Descrição:</strong> ${escapeHtml(item.description)}<br />
        ${internalNoteDisplay}
      </td>
      <td>
        <div class="row-actions">
          <button class="btn secondary" onclick="changeStatus('${escapeHtml(item.id)}', 'Em análise')">Em análise</button>
          <button class="btn secondary" onclick="changeStatus('${escapeHtml(item.id)}', 'Resolvida')">Resolver</button>
          <button class="btn danger"    onclick="deleteOccurrence('${escapeHtml(item.id)}')">Excluir</button>
        </div>
      </td>
    </tr>
  `;
  }).join("");

  // ── Logs de auditoria
  const logs = getAuditLogs();

  if (logs.length === 0) {
    auditLog.innerHTML = `<div class="notice">Nenhum log registrado.</div>`;
  } else {
    // MELHORIA 11: logs já chegam com CPF mascarado (aplicado em writeLog)
    auditLog.innerHTML = logs.map((log) => `
      <div class="log-item">
        <strong>${escapeHtml(log.when)}</strong><br />
        usuário=${escapeHtml(log.user || "—")} | perfil=${escapeHtml(log.role || "—")} | ação=${escapeHtml(log.action)}<br />
        detalhe=${escapeHtml(log.detail)}
      </div>
    `).join("");
  }
}

// ── Event listeners ───────────────────────────────────────────────────────────
loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  login(
    document.querySelector("#email").value,
    document.querySelector("#password").value
  );
});

occurrenceForm.addEventListener("submit", createOccurrence);
logoutBtn.addEventListener("click", logout);
exportBtn.addEventListener("click", exportEverything);
clearLogsBtn.addEventListener("click", clearLogs);
resetBtn.addEventListener("click", resetData);
searchInput.addEventListener("input", render);
roleSelect.addEventListener("change", (event) => changeRole(event.target.value));

// Exposição global necessária para os botões inline na tabela
window.deleteOccurrence = deleteOccurrence;
window.changeStatus     = changeStatus;

// Inicializa
boot();
