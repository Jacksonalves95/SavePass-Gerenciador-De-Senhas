🔐 SavePass — Gerenciador de Senhas Pessoal
Desenvolvido por Jackson Alves · © 2026

SavePass é um gerenciador de senhas local, seguro e elegante desenvolvido em Python com interface gráfica Tkinter. Todo o armazenamento é feito localmente com criptografia de nível profissional.

📸 Funcionalidades

🔐 Autenticação	Login e cadastro com validação completa
🗂 Carteira	Até 10 credenciais por usuário
👁 Privacidade	Senhas mascaradas com toggle de visibilidade
⚡ Gerador	Gerador de senhas fortes integrado
📋 Clipboard	Cópia de senha com 1 clique
📂 Categorias	Organização por tipo (Trabalho, Banco, Social…)
⚙ Configurações Bloqueio automático, clipboard, força de senha
🛡 Segurança
KDF: PBKDF2-HMAC-SHA256 com 480.000 iterações
Criptografia: Fernet (AES-128-CBC + HMAC-SHA256)
Senhas: Armazenadas com hash + salt único de 32 bytes
Verificação: HMAC com compare_digest (resistente a timing attacks)
Chave por usuário: Derivada da senha mestra, nunca armazenada
Validação: Mínimo 8 caracteres, maiúsculas, minúsculas, número e especial
🚀 Instalação
Pré-requisitos
Python 3.10 ou superior
Tkinter (incluso no Python padrão no Windows/macOS)
Linux: sudo apt install python3-tk
Instalar dependências
bash
pip install -r requirements.txt
Executar
bash
python savepass.py
📁 Estrutura
SavePass/
├── savepass.py          # Código principal
├── requirements.txt     # Dependências
├── logosavepass1.jpg    # Logo do app (coloque aqui)
├── README.md
└── data/
    └── users.json       # Dados criptografados (criado automaticamente)
🖼 Logo
Coloque o arquivo logosavepass1.jpg na mesma pasta do savepass.py.
Se o arquivo não for encontrado, o app exibirá o nome "SavePass" estilizado automaticamente.

🎨 Design
Tema: Dark Mode — paleta azul e preta
Cor primária: 
#2563EB (azul profundo)
Background: 
#0A0D14 (preto azulado)
Cards: 
#141926
Tipografia: Segoe UI / Consolas (mono para credenciais)
Indicador visual de força de senha em tempo real
Toast notifications com feedback de ações
Badges coloridos por categoria de credencial
📝 Melhorias implementadas 
Categorias de credenciais — organize por tipo com badges coloridos
Gerador de senha forte — ⚡ botão em todos os campos de senha
Anotações — campo de nota livre por credencial
Toast notifications — feedback visual sem interromper o fluxo
Copiar senha — botão ⧉ para copiar sem revelar na tela
Barra de força de senha — indicador em tempo real em 5 níveis
Painel de estatísticas — cards com resumo da carteira
Badge de usuário — iniciais no header
Limpar clipboard ao sair — opção de segurança nas configurações
Validação de e-mail — regex padrão RFC
SavePass — Porque suas senhas merecem um cofre de verdade.
