/**
 * Email Organizer - JavaScript
 * Funcionalidades interativas
 */

// ===== Progress Bar Global =====
const progressBar = document.createElement('div');
progressBar.id = 'global-progress';
progressBar.innerHTML = `
    <div class="progress-bar">
        <div class="progress-fill"></div>
    </div>
    <div class="progress-text">Processando...</div>
`;
progressBar.style.display = 'none';
document.body.prepend(progressBar);

// Função para mostrar barra de progresso
function showProgress(message = 'Processando...', progress = null) {
    const bar = document.getElementById('global-progress');
    const fill = bar.querySelector('.progress-fill');
    const text = bar.querySelector('.progress-text');

    text.textContent = message;
    bar.style.display = 'block';

    if (progress !== null) {
        // Progresso determinado (0-100)
        fill.style.width = `${progress}%`;
        fill.classList.remove('indeterminate');
    } else {
        // Progresso indeterminado (animação)
        fill.style.width = '100%';
        fill.classList.add('indeterminate');
    }
}

// Função para esconder barra de progresso
function hideProgress() {
    const bar = document.getElementById('global-progress');
    bar.style.display = 'none';
}

// Função para atualizar progresso
function updateProgress(message, progress) {
    const bar = document.getElementById('global-progress');
    const fill = bar.querySelector('.progress-fill');
    const text = bar.querySelector('.progress-text');

    if (message) text.textContent = message;
    if (progress !== null && progress !== undefined) {
        fill.style.width = `${progress}%`;
        fill.classList.remove('indeterminate');
    }
}

// Fechar flash messages automaticamente após 5 segundos
document.querySelectorAll('.flash').forEach(flash => {
    setTimeout(() => {
        flash.style.opacity = '0';
        setTimeout(() => flash.remove(), 300);
    }, 5000);
});

// Adiciona efeito de loading nos botões ao clicar
document.querySelectorAll('.btn-primary').forEach(btn => {
    btn.addEventListener('click', function () {
        if (this.form && !this.form.checkValidity()) {
            return;
        }
        if (this.type === 'submit') {
            this.classList.add('loading');
        }
    });
});

// Checkbox customizado
document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
    checkbox.addEventListener('change', function () {
        this.closest('label')?.classList.toggle('checked', this.checked);
    });
});

// Keyboard shortcuts
document.addEventListener('keydown', function (e) {
    // Ctrl/Cmd + K para ir para dashboard
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        window.location.href = '/dashboard';
    }

    // Esc para fechar modais
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal:not(.hidden)').forEach(modal => {
            modal.classList.add('hidden');
        });
    }
});

// Função para copiar texto
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copiado!', 'success');
    }).catch(() => {
        showToast('Erro ao copiar', 'error');
    });
}

// Toast notifications
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('show');
    }, 10);

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Adiciona estilos dinamicamente
const dynamicStyles = document.createElement('style');
dynamicStyles.textContent = `
    /* Progress Bar Global */
    #global-progress {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        z-index: 9999;
        background: var(--bg-secondary, #1a1a2e);
        padding: 0.75rem 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        animation: slideDown 0.3s ease;
    }
    
    @keyframes slideDown {
        from {
            transform: translateY(-100%);
            opacity: 0;
        }
        to {
            transform: translateY(0);
            opacity: 1;
        }
    }
    
    .progress-bar {
        height: 6px;
        background: var(--bg-tertiary, #252542);
        border-radius: 3px;
        overflow: hidden;
        margin-bottom: 0.5rem;
    }
    
    .progress-fill {
        height: 100%;
        background: linear-gradient(90deg, #6366f1, #a855f7, #6366f1);
        background-size: 200% 100%;
        border-radius: 3px;
        transition: width 0.3s ease;
    }
    
    .progress-fill.indeterminate {
        animation: progressIndeterminate 1.5s ease-in-out infinite;
    }
    
    @keyframes progressIndeterminate {
        0% {
            background-position: 200% 0;
        }
        100% {
            background-position: -200% 0;
        }
    }
    
    .progress-text {
        font-size: 0.875rem;
        color: var(--text-secondary, #a0a0b5);
        text-align: center;
    }
    
    /* Toast notifications */
    .toast {
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: var(--bg-card, #1e1e35);
        border-radius: 8px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
        color: var(--text-primary, #f0f0f5);
        transform: translateY(100px);
        opacity: 0;
        transition: all 0.3s ease;
        z-index: 2000;
    }
    
    .toast.show {
        transform: translateY(0);
        opacity: 1;
    }
    
    .toast-success {
        border-left: 4px solid #22c55e;
    }
    
    .toast-error {
        border-left: 4px solid #ef4444;
    }
    
    .toast-info {
        border-left: 4px solid #3b82f6;
    }

    /* Modal System */
    .modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.7);
        backdrop-filter: blur(4px);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s ease;
    }

    .modal-overlay.show {
        opacity: 1;
        visibility: visible;
    }

    .modal-container {
        background: #ffffff;
        border-radius: 16px;
        padding: 0;
        max-width: 400px;
        width: 90%;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        transform: scale(0.95) translateY(10px);
        transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        overflow: hidden;
        border: 1px solid #e2e8f0;
    }

    .modal-overlay.show .modal-container {
        transform: scale(1) translateY(0);
    }

    .modal-header {
        padding: 1.5rem 1.5rem 0.75rem;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.75rem;
        text-align: center;
    }

    .modal-icon {
        width: 52px;
        height: 52px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        flex-shrink: 0;
    }

    .modal-icon.info { background: #e0f2fe; }
    .modal-icon.success { background: #d1fae5; }
    .modal-icon.warning { background: #fef3c7; }
    .modal-icon.error { background: #fee2e2; }
    .modal-icon.confirm { background: #ede9fe; }

    .modal-title {
        font-size: 1.125rem;
        font-weight: 600;
        color: #0f172a;
        margin: 0;
        letter-spacing: -0.02em;
    }

    .modal-body {
        padding: 0.5rem 1.5rem 1.5rem;
    }

    .modal-message {
        color: #475569;
        font-size: 0.9375rem;
        line-height: 1.6;
        margin: 0;
        text-align: center;
    }

    .modal-footer {
        padding: 0 1.5rem 1.5rem;
        display: flex;
        gap: 0.75rem;
        justify-content: center;
    }

    .modal-btn {
        padding: 0.625rem 1.25rem;
        border-radius: 8px;
        font-size: 0.875rem;
        font-weight: 600;
        cursor: pointer;
        border: none;
        transition: all 0.15s ease;
        min-width: 100px;
    }

    .modal-btn-secondary {
        background: #f1f5f9;
        color: #0f172a;
        border: 1px solid #e2e8f0;
    }

    .modal-btn-secondary:hover {
        background: #e2e8f0;
    }

    .modal-btn-primary {
        background: #2563eb;
        color: white;
    }

    .modal-btn-primary:hover {
        background: #1d4ed8;
    }

    .modal-btn-danger {
        background: #ef4444;
        color: white;
    }

    .modal-btn-danger:hover {
        background: #dc2626;
    }
`;
document.head.appendChild(dynamicStyles);

// ===== Modal System =====
const modalOverlay = document.createElement('div');
modalOverlay.className = 'modal-overlay';
modalOverlay.id = 'modal-overlay';
modalOverlay.innerHTML = `
    <div class="modal-container">
        <div class="modal-header">
            <div class="modal-icon info" id="modal-icon">ℹ️</div>
            <h3 class="modal-title" id="modal-title">Título</h3>
        </div>
        <div class="modal-body">
            <p class="modal-message" id="modal-message">Mensagem</p>
        </div>
        <div class="modal-footer" id="modal-footer">
            <button class="modal-btn modal-btn-primary" id="modal-ok">OK</button>
        </div>
    </div>
`;
document.body.appendChild(modalOverlay);

// Fechar modal ao clicar no overlay
modalOverlay.addEventListener('click', function (e) {
    if (e.target === modalOverlay) {
        closeModal(false);
    }
});

let modalResolve = null;

function closeModal(result = true) {
    const overlay = document.getElementById('modal-overlay');
    overlay.classList.remove('show');
    if (modalResolve) {
        modalResolve(result);
        modalResolve = null;
    }
}

// Função showModal - substitui alert()
function showModal(message, options = {}) {
    return new Promise((resolve) => {
        modalResolve = resolve;

        const {
            title = 'Aviso',
            type = 'info',
            confirmText = 'OK',
            showCancel = false,
            cancelText = 'Cancelar',
            isDanger = false
        } = options;

        const icons = {
            info: 'ℹ️',
            success: '✅',
            warning: '⚠️',
            error: '❌',
            confirm: '❓'
        };

        const modalIcon = document.getElementById('modal-icon');
        const modalTitle = document.getElementById('modal-title');
        const modalMessage = document.getElementById('modal-message');
        const modalFooter = document.getElementById('modal-footer');

        modalIcon.textContent = icons[type] || icons.info;
        modalIcon.className = `modal-icon ${type}`;
        modalTitle.textContent = title;
        modalMessage.textContent = message;

        // Configura botões
        if (showCancel) {
            modalFooter.innerHTML = `
                <button class="modal-btn modal-btn-secondary" id="modal-cancel">${cancelText}</button>
                <button class="modal-btn ${isDanger ? 'modal-btn-danger' : 'modal-btn-primary'}" id="modal-ok">${confirmText}</button>
            `;
            document.getElementById('modal-cancel').addEventListener('click', () => closeModal(false));
        } else {
            modalFooter.innerHTML = `
                <button class="modal-btn modal-btn-primary" id="modal-ok">${confirmText}</button>
            `;
        }

        document.getElementById('modal-ok').addEventListener('click', () => closeModal(true));

        // Mostra modal
        document.getElementById('modal-overlay').classList.add('show');
        document.getElementById('modal-ok').focus();
    });
}

// Função showConfirm - substitui confirm()
function showConfirm(message, options = {}) {
    return showModal(message, {
        title: options.title || 'Confirmar',
        type: 'confirm',
        confirmText: options.confirmText || 'Sim',
        cancelText: options.cancelText || 'Não',
        showCancel: true,
        isDanger: options.isDanger || false
    });
}

// Função showAlert - versão simplificada de showModal
function showAlert(message, type = 'info') {
    const titles = {
        info: 'Informação',
        success: 'Sucesso',
        warning: 'Atenção',
        error: 'Erro'
    };
    return showModal(message, { title: titles[type], type });
}

console.log('📧 Email Organizer loaded successfully');

