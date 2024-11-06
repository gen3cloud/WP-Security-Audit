# WP Security Audit Script

Este script é utilizado para verificar a integridade dos arquivos em sites WordPress hospedados em servidores cPanel. Ele remove arquivos comprometidos e mantém arquivos críticos, como `wp-config.php`.

## Funcionalidades

- Verifica a integridade dos arquivos do WordPress com o comando `wp core verify-checksums`.
- Remove arquivos comprometidos que não devem existir.
- Permite a execução paralela para otimizar o tempo de execução.
- Registra todas as ações no arquivo de log.
- Possui uma lista de arquivos críticos que não são removidos.
- Verifica sub-sites associados à conta cPanel.

## Como Usar

1. Clone este repositório:
   ```bash
   git clone https://github.com/seu-usuario/wp_security_audit.git
   cd wp_security_audit
   
2. Torne o script executável:

chmod +x wp_security_audit.sh

Execute o script:

./wp_security_audit.sh

## Configuração

No início do script, você pode ajustar as seguintes variáveis:

LOG_FILE: Caminho do arquivo de log.

MAX_PARALLEL_PROCESSES: Número máximo de processos simultâneos.

CRITICAL_FILES: Arquivos que não serão removidos, mesmo que comprometidos.

## Licença

Este projeto está licenciado sob a Licença MIT.
