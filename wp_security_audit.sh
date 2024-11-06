#!/bin/bash

# ============================
# WP Security Audit Script
# ============================
# Este script verifica a integridade de arquivos do WordPress em contas cPanel,
# removendo arquivos comprometidos que não devem existir de acordo com as verificações
# de integridade do WP (wp core verify-checksums).
# O script também realiza a execução paralela para otimizar o tempo de execução.
# Autor: [Seu Nome]
# Data: [Data]
# ============================

# ============================
# Variáveis de Configuração
# ============================
LOG_FILE="/var/log/wp_security_audit.log"  # Arquivo de log
MAX_PARALLEL_PROCESSES=4  # Número máximo de processos simultâneos
CRITICAL_FILES=("wp-config.php" "wp-content/uploads" "wp-content/themes/custom-theme/functions.php")  # Arquivos que não devem ser removidos

# Função para gerar log
log_action() {
    echo "$(date) - $1" >> $LOG_FILE
}

# Função para verificar a integridade dos arquivos do WordPress
verify_checksums() {
    local path=$1
    local user=$2
    su -s /bin/bash -c "wp core verify-checksums --path=${path}" ${user}
}

# Função para verificar se o arquivo está na lista de arquivos críticos
is_whitelisted() {
    for file in "${CRITICAL_FILES[@]}"; do
        if [[ "$1" == "$file" ]]; then
            return 0
        fi
    done
    return 1
}

# Função para verificar e remover arquivos comprometidos
verify_and_remove_files() {
    local user=$1
    local path="/home/${user}/public_html"

    # Verificar a integridade dos arquivos do WordPress
    sketchy=$(verify_checksums "${path}" "${user}" 2>&1 | grep 'File should not exist' | awk -F' ' '{print $NF}')
    
    # Remover arquivos comprometidos
    for sketch in $sketchy; do
        if ! is_whitelisted "$sketch"; then
            echo "++ Removendo arquivo: ${path}/${sketch}"
            rm -f "${path}/${sketch}"
            log_action "Arquivo removido: ${path}/${sketch}"
        else
            log_action "Arquivo preservado: ${path}/${sketch}"
        fi
    done
}

# Função para verificar sites secundários (sub-sites)
verify_subsites() {
    local user=$1
    local path="/home/${user}/public_html"

    # Encontrar todos os wp-config.php para sites secundários
    for subsite in $(find "${path}" -name "wp-config.php" | grep -Po "/home/${user}/public_html/\K.*(?=/wp-config.php)"); do
        local subsite_path="${path}/${subsite}"
        echo "Verificando sub-site: ${subsite}"

        # Verificar a integridade do sub-site
        sketchy=$(verify_checksums "${subsite_path}" "${user}" 2>&1 | grep 'File should not exist' | awk -F' ' '{print $NF}')
        
        # Remover arquivos comprometidos do sub-site
        for sketch in $sketchy; do
            if ! is_whitelisted "$sketch"; then
                echo "++ Removendo arquivo: ${subsite_path}/${sketch}"
                rm -f "${subsite_path}/${sketch}"
                log_action "Arquivo removido: ${subsite_path}/${sketch}"
            else
                log_action "Arquivo preservado: ${subsite_path}/${sketch}"
            fi
        done
    done
}

# ============================
# Início da Execução
# ============================
echo "Iniciando auditoria de segurança do WordPress..."
log_action "Início da auditoria: $(date)"

# Obter lista de contas de usuário cPanel
users=$( /usr/local/cpanel/bin/apitool listaccts --output json | jq -r '.data.acct[] | select(.suspended == 0) | .user' )

# Verificar e remover arquivos para cada conta de usuário
echo "$users" | xargs -I {} -P ${MAX_PARALLEL_PROCESSES} bash -c 'verify_and_remove_files "{}"; verify_subsites "{}";'

# Gerar relatório
log_action "Auditoria de segurança concluída: $(date)"
echo "Auditoria de segurança concluída. Relatório gerado em $LOG_FILE."

