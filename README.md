# Sistema de Preview Robusto

Este é um servidor de preview robusto e otimizado para deploy em plataformas como o Render.com. Ele permite que você gere URLs de preview para seus projetos front-end (React, Vite, Astro, etc.) de forma dinâmica, com tratamento de erros, logging e segurança aprimorada.

## Funcionalidades

- **Geração de URLs de Preview**: Recebe arquivos de projetos front-end via POST e retorna uma URL de preview.
- **Suporte a Múltiplos Frameworks**: Detecta e configura automaticamente projetos Vite e Astro para funcionar corretamente em subdiretórios.
- **Tratamento de Erros Robusto**: Captura e loga erros de forma centralizada.
- **Segurança Aprimorada**: Inclui CORS, Helmet e Rate Limiting.
- **Logging Detalhado**: Utiliza Winston para logs estruturados.
- **Limpeza Automática**: Remove previews antigos para economizar espaço.
- **Configuração Flexível**: Permite configurar portas, diretórios e limites via variáveis de ambiente.

## Estrutura do Projeto

```
.env.example
.gitignore
package.json
server.js
/logs
/previews
```

- `server.js`: O arquivo principal do servidor, contendo toda a lógica.
- `package.json`: Define as dependências e scripts do projeto.
- `.env.example`: Exemplo de variáveis de ambiente para configuração.
- `.gitignore`: Configura arquivos e pastas a serem ignorados pelo Git.
- `/logs`: Diretório para os logs do servidor.
- `/previews`: Diretório onde os projetos de preview são armazenados temporariamente.

## Como Usar (Localmente)

1.  **Clone o repositório** (ou descompacte o ZIP).
2.  **Instale as dependências**:
    ```bash
    npm install
    ```
3.  **Inicie o servidor**:
    ```bash
    npm start
    ```
    O servidor estará disponível em `http://localhost:3001`.

## Como Fazer Deploy no Render.com

Siga estes passos para fazer o deploy do seu servidor no Render.com:

1.  **Crie um Novo Repositório no GitHub**:
    *   Vá para o GitHub e crie um **novo repositório vazio** (sem `README.md`, `.gitignore` ou licença).
    *   Dê um nome significativo, como `preview-server`.

2.  **Faça o Upload dos Arquivos para o GitHub**:
    *   Na sua máquina local, certifique-se de que a pasta `node_modules` **NÃO EXISTE** dentro do diretório do projeto (`preview-server-final`). Se existir, delete-a.
    *   Arraste e solte **TODO o conteúdo** do diretório `preview-server-final` (incluindo `server.js`, `package.json`, `.env.example`, `.gitignore`, e as pastas `logs` e `previews`) diretamente para a interface de upload do seu **novo repositório vazio** no GitHub.
    *   Certifique-se de que os arquivos `server.js` e `package.json` estejam na **raiz** do repositório, e não dentro de uma subpasta.

3.  **Configure o Serviço no Render.com**:
    *   Vá para o seu painel do Render.com.
    *   Clique em **"New Web Service"**.
    *   Conecte-se ao **novo repositório** que você acabou de criar no GitHub.
    *   **Nome do Serviço**: `preview-server` (ou o nome que preferir).
    *   **Region**: Escolha a região mais próxima de você.
    *   **Branch**: `main` (ou a branch que você usou).
    *   **Root Directory**: Deixe em branco (ou `./`).
    *   **Runtime**: `Node`.
    *   **Build Command**: `npm install --no-optional`
    *   **Start Command**: `npm start`

4.  **Adicione Variáveis de Ambiente no Render.com**:
    *   Após criar o serviço, vá para a aba **"Environment"** no menu lateral do seu serviço no Render.com.
    *   Adicione as seguintes variáveis:
        *   **Key**: `PORT`  **Value**: `10000` (Esta é a porta que o Render.com espera que seu serviço escute).
        *   **Key**: `NODE_ENV`  **Value**: `production`
        *   **Key**: `NODE_VERSION`  **Value**: `20.x.x` (ou a versão mais recente estável, como `20.13.1`).

5.  **Implante o Serviço**:
    *   Vá para a aba **"Events"** ou **"Deploys"**.
    *   Clique em **"Manual Deploy"** e selecione **"Deploy latest commit"**.

## Testando o Servidor de Preview

Depois que o deploy for bem-sucedido no Render.com, você terá uma URL para o seu servidor (ex: `https://seu-servico.onrender.com`).

Para testar, você pode usar o arquivo `basic_site_payload_updated.json` que eu te forneci anteriormente. Substitua `SUA_URL_DO_RENDER` pela URL do seu serviço no Render.com:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d @basic_site_payload_updated.json \
  SUA_URL_DO_RENDER/build
```

O servidor retornará uma URL de preview (ex: `https://seu-servico.onrender.com/preview/ID_DO_PROJETO/dist/`). Abra essa URL no seu navegador para ver o site de teste funcionando.

Se tiver qualquer problema, verifique os logs do seu serviço no Render.com e entre em contato.

