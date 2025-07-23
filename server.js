import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Joi from 'joi';
import winston from 'winston';
import { nanoid } from 'nanoid';
import archiver from 'archiver';
import path from 'path';
import { promises as fs } from 'fs';
import { createWriteStream } from 'fs';
import { spawn } from 'child_process';

// Configuração
const config = {
  port: process.env.PORT || 3000,
  tempDir: path.join(process.cwd(), 'temp'),
  logsDir: path.join(process.cwd(), 'logs'),
  buildTimeout: 300000, // 5 minutos
  maxFileSize: 10 * 1024 * 1024, // 10MB por arquivo
  maxFiles: 100
};

// Configuração do logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'build-and-zip-server' },
  transports: [
    new winston.transports.File({ filename: path.join(config.logsDir, 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(config.logsDir, 'combined.log') }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Criar diretórios necessários
await fs.mkdir(config.tempDir, { recursive: true });
await fs.mkdir(config.logsDir, { recursive: true });

const app = express();

// Lista de origens permitidas
const allowedOrigins = [
  'https://lovableproject.com',
  'http://localhost:3000',
  'http://localhost:5173'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Permite requisições sem 'origin' (ex: Postman, curl)
    if (!origin) {
      return callback(null, true);
    }

    // Verifica se a origem está na lista de permitidas estáticas
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // CORREÇÃO: Verifica se a origem é um subdomínio de 'lovable.app'
    const lovableAppDomain = 'lovable.app';
    if (origin.endsWith(`.${lovableAppDomain}`)) {
      return callback(null, true);
    }

    // Se a origem não for permitida de forma alguma
    const msg = `A política de CORS para este site não permite acesso da origem: ${origin}`;
    logger.warn('Requisição de CORS bloqueada', { origin });
    return callback(new Error(msg), false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
};

// Aplica o middleware CORS com as opções configuradas
app.use(cors(corsOptions));

// Middlewares de segurança
app.use(helmet());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // máximo 10 requisições por IP por janela de tempo
  message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/build-and-download', limiter);

// Middleware de logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  next();
});

// Schema de validação
const buildRequestSchema = Joi.object({
  files: Joi.object().pattern(
    Joi.string(),
    Joi.string().max(config.maxFileSize)
  ).max(config.maxFiles).required()
});

// Função para executar comandos
const executeCommand = (command, args, cwd, timeout = config.buildTimeout) => {
  return new Promise((resolve, reject) => {
    const fullCommand = `${command} ${args.join(' ')}`;
    logger.info(`Executando comando: ${fullCommand}`, { cwd });

    const process = spawn(fullCommand, [], { 
      cwd, 
      shell: true,
      stdio: 'pipe'
    });
    
    let stdout = '';
    let stderr = '';
    
    process.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    process.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    const timer = setTimeout(() => {
      process.kill('SIGKILL');
      reject(new Error(`Comando expirou após ${timeout}ms`));
    }, timeout);
    
    process.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) {
        logger.info(`Comando concluído com sucesso`, { command, code });
        resolve({ stdout, stderr, code });
      } else {
        logger.error(`Comando falhou`, { command, code, stderr, stdout });
        reject(new Error(`Comando falhou com código ${code}: ${stderr}`));
      }
    });
    
    process.on('error', (error) => {
      clearTimeout(timer);
      logger.error(`Erro ao executar comando`, { command, error: error.message });
      reject(error);
    });
  });
};

// Função para instalar dependências
const installDependencies = async (projectDir) => {
  logger.info('Instalando TODAS as dependências (incluindo dev)', { projectDir });

  try {
    await executeCommand('npm', ['install', '--include=dev'], projectDir);
    logger.info('Dependências instaladas com npm (incluindo dev)');
  } catch (npmError) {
    logger.error('Falha ao instalar dependências com npm', { npmError: npmError.message });
    throw new Error(`Falha ao instalar dependências: ${npmError.message}`);
  }
};

// Função para fazer o build
const runBuild = async (projectDir) => {
  logger.info('Iniciando build com caminho explícito para o Vite', { projectDir });

  // Caminho absoluto e explícito para o executável do Vite dentro do projeto temporário
  const viteExecutablePath = path.join(projectDir, 'node_modules', '.bin', 'vite');

  try {
    // Verificar se o executável do Vite realmente existe após o 'npm install'
    await fs.access(viteExecutablePath);
    logger.info(`Executável do Vite encontrado em: ${viteExecutablePath}`);
  } catch (accessError) {
    logger.error('CRÍTICO: O executável do Vite não foi encontrado após a instalação das dependências.', {
      path: viteExecutablePath,
      error: accessError.message
    });
    throw new Error('Falha crítica: vite não foi instalado corretamente em node_modules/.bin.');
  }

  try {
    // Executar o Vite DIRETAMENTE pelo seu caminho absoluto
    await executeCommand(viteExecutablePath, ['build'], projectDir);
    logger.info('Build concluído com sucesso usando caminho explícito do Vite.');
  } catch (buildError) {
    logger.error('Build falhou mesmo com caminho explícito do Vite.', {
      error: buildError.message,
      projectDir
    });
    throw new Error(`Build falhou: ${buildError.message}`);
  }
};

// Função para criar ZIP da pasta dist
const createZipFromDist = (projectDir) => {
  return new Promise((resolve, reject) => {
    const distPath = path.join(projectDir, 'dist');
    const zipPath = path.join(projectDir, 'deploy.zip');
    
    logger.info('Criando ZIP da pasta dist', { distPath, zipPath });
    
    const output = createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });
    
    output.on('close', () => {
      const sizeInBytes = archive.pointer();
      logger.info(`ZIP criado com sucesso: ${zipPath} (${sizeInBytes} bytes)`);
      resolve(zipPath);
    });
    
    archive.on('error', (err) => {
      logger.error('Erro ao criar ZIP', { error: err.message });
      reject(err);
    });
    
    archive.pipe(output);
    archive.directory(distPath, false);
    archive.finalize();
  });
};

// Rota de saúde
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'build-and-zip-server'
  });
});

// Rota principal de build e download
app.post('/build-and-download', async (req, res) => {
  const buildId = nanoid();
  const projectDir = path.join(config.tempDir, buildId);
  
  logger.info('Requisição de build e download recebida', { buildId });
  
  try {
    // Validar entrada
    const { error, value } = buildRequestSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ 
        error: 'Dados inválidos', 
        details: error.details.map(d => d.message) 
      });
    }
    
    const { files } = value;
    
    logger.info('Criando projeto para build', { 
      buildId, 
      fileCount: Object.keys(files).length 
    });
    
    // Criar diretório do projeto
    await fs.mkdir(projectDir, { recursive: true });
    
    // Escrever arquivos
    await Promise.all(
      Object.entries(files).map(async ([filePath, content]) => {
        const cleanPath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
        const fullPath = path.join(projectDir, cleanPath);
        const dir = path.dirname(fullPath);
        
        await fs.mkdir(dir, { recursive: true });
        await fs.writeFile(fullPath, content, 'utf8');
      })
    );
    
    logger.info('Arquivos escritos, iniciando build', { buildId });
    
    // Instalar dependências
    await installDependencies(projectDir);
    
    // Fazer build
    await runBuild(projectDir);
    
    // Verificar se o build foi bem-sucedido
    const distPath = path.join(projectDir, 'dist');
    const indexPath = path.join(distPath, 'index.html');
    
    try {
      await fs.access(indexPath);
      logger.info('Build verificado: index.html encontrado', { buildId });
    } catch {
      throw new Error('Build falhou: index.html não encontrado na pasta dist');
    }
    
    // Criar ZIP da pasta dist
    const zipPath = await createZipFromDist(projectDir);
    
    // Enviar o arquivo ZIP como resposta
    logger.info(`Enviando arquivo ZIP para o cliente: ${zipPath}`, { buildId });

    const downloadFileName = `deploy-${buildId}.zip`;

    res.download(zipPath, downloadFileName, (err) => {
      if (err) {
        logger.error('Erro ao enviar o arquivo ZIP para o cliente', { buildId, error: err.message });
      } else {
        logger.info(`Arquivo ZIP ${downloadFileName} enviado com sucesso.`, { buildId });
      }

      // Limpeza da pasta temporária após o envio
      fs.rm(projectDir, { recursive: true, force: true })
        .then(() => logger.info(`Pasta temporária de build removida: ${buildId}`))
        .catch(cleanupError => logger.error('Erro na limpeza após download', { buildId, error: cleanupError.message }));
    });
    
  } catch (error) {
    logger.error('Erro no processo de build e zip', { buildId, error: error.message, stack: error.stack });
    
    // Se der erro ANTES do download, remove a pasta imediatamente
    await fs.rm(projectDir, { recursive: true, force: true }).catch(() => {});

    res.status(500).json({
      error: 'Falha no processo de build',
      message: error.message,
      buildId
    });
  }
});

// Middleware de tratamento de erros
app.use((error, req, res, next) => {
  logger.error('Erro não tratado', { error: error.message, stack: error.stack });
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// Middleware para rotas não encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// Iniciar servidor
app.listen(config.port, '0.0.0.0', () => {
  logger.info(`Servidor de build e zip rodando na porta ${config.port}`);
});

// Tratamento de sinais para encerramento gracioso
process.on('SIGTERM', () => {
  logger.info('SIGTERM recebido, encerrando servidor...');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT recebido, encerrando servidor...');
  process.exit(0);
});
