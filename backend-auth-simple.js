// Backend simplificado para autenticação e gerenciamento de contas do Cloudim
// Usando JSON para armazenamento em vez de MongoDB
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Caminho para o arquivo de usuários
const USERS_FILE = path.join(__dirname, 'users.json');

// Função para ler usuários do arquivo
async function readUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    // Se o arquivo não existir, retorna array vazio
    if (error.code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

// Função para escrever usuários no arquivo
async function writeUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Rotas

// Registro de novo usuário
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validação básica
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
    }

    // Ler usuários existentes
    const users = await readUsers();

    // Verificar se o usuário já existe
    const existingUser = users.find(u => u.email === email || u.username === username);
    if (existingUser) {
      return res.status(409).json({ error: 'Usuário ou email já cadastrado' });
    }

    // Criptografar senha
    const hashedPassword = await bcrypt.hash(password, 12);

    // Criar novo usuário
    const newUser = {
      id: Date.now().toString(), // ID simples baseado no timestamp
      username,
      email,
      password: hashedPassword,
      storageUsed: 0,
      storageLimit: 1099511627776, // 1TB em bytes
      createdAt: new Date().toISOString(),
      isActive: true,
      settings: {
        autoSync: false,
        notifications: true,
        theme: 'light'
      }
    };

    // Salvar usuário
    users.push(newUser);
    await writeUsers(users);

    // Gerar token JWT
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      process.env.JWT_SECRET || 'cloudim-secret-key',
      { expiresIn: '7d' }
    );

    // Retornar resposta com token e dados do usuário (sem senha)
    const { password: _, ...userData } = newUser;
    res.status(201).json({
      message: 'Conta criada com sucesso!',
      token,
      user: userData
    });
  } catch (error) {
    console.error('Erro ao registrar usuário:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    // Ler usuários
    const users = await readUsers();
    
    // Encontrar usuário
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Verificar senha
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Gerar token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET || 'cloudim-secret-key',
      { expiresIn: '7d' }
    );

    // Retornar resposta com token e dados do usuário (sem senha)
    const { password: _, ...userData } = user;
    res.json({
      message: 'Login bem-sucedido!',
      token,
      user: userData
    });
  } catch (error) {
    console.error('Erro ao fazer login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Middleware de autenticação
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'cloudim-secret-key', async (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    try {
      const users = await readUsers();
      const user = users.find(u => u.id === decoded.userId);
      
      if (!user) {
        return res.status(401).json({ error: 'Usuário não encontrado' });
      }

      req.user = user;
      next();
    } catch (error) {
      res.status(500).json({ error: 'Erro ao verificar usuário' });
    }
  });
}

// Verificação de token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  const { password: _, ...userData } = req.user;
  res.json({ user: userData });
});

// Obter informações do usuário
app.get('/api/user/profile', authenticateToken, (req, res) => {
  const { password: _, ...userData } = req.user;
  res.json({ user: userData });
});

// Atualizar perfil do usuário
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const users = await readUsers();
    const userIndex = users.findIndex(u => u.id === req.user.id);
    
    if (userIndex === -1) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Atualizar campos permitidos
    const allowedUpdates = ['username', 'email', 'settings'];
    
    for (const key in req.body) {
      if (allowedUpdates.includes(key)) {
        users[userIndex][key] = req.body[key];
      }
    }

    await writeUsers(users);

    const { password: __, ...updatedUserData } = users[userIndex];
    res.json({
      message: 'Perfil atualizado com sucesso!',
      user: updatedUserData
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// Rota para obter estatísticas do usuário
app.get('/api/user/stats', authenticateToken, (req, res) => {
  res.json({
    stats: {
      storageUsed: req.user.storageUsed,
      storageLimit: req.user.storageLimit,
      storagePercentage: Math.round((req.user.storageUsed / req.user.storageLimit) * 100),
      filesCount: Math.floor(Math.random() * 100), // Simulação
      foldersCount: Math.floor(Math.random() * 20), // Simulação
      lastActivity: new Date().toISOString()
    }
  });
});

// Rota de exemplo para upload de arquivo (simulação)
app.post('/api/files/upload', authenticateToken, async (req, res) => {
  try {
    const { filename, size } = req.body;
    
    if (!filename || !size) {
      return res.status(400).json({ error: 'Nome do arquivo e tamanho são obrigatórios' });
    }

    const users = await readUsers();
    const userIndex = users.findIndex(u => u.id === req.user.id);
    
    if (userIndex === -1) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Simular aumento do espaço utilizado
    const newSize = users[userIndex].storageUsed + parseInt(size);
    if (newSize > users[userIndex].storageLimit) {
      return res.status(400).json({ error: 'Limite de armazenamento excedido' });
    }
    
    users[userIndex].storageUsed = newSize;
    await writeUsers(users);

    res.json({
      message: 'Arquivo enviado com sucesso!',
      file: {
        id: Math.random().toString(36).substr(2, 9),
        name: filename,
        size: parseInt(size),
        uploadedAt: new Date().toISOString(),
        url: `/files/${Math.random().toString(36).substr(2, 9)}`
      },
      storage: {
        used: users[userIndex].storageUsed,
        limit: users[userIndex].storageLimit,
        percentage: Math.round((users[userIndex].storageUsed / users[userIndex].storageLimit) * 100)
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao fazer upload' });
  }
});

// Rota para obter lista de arquivos (simulação)
app.get('/api/files', authenticateToken, (req, res) => {
  // Simular lista de arquivos
  const files = [
    { id: 'file1', name: 'documento.pdf', size: 2048576, type: 'application/pdf', uploadedAt: '2023-01-15T10:30:00Z' },
    { id: 'file2', name: 'imagem.jpg', size: 1048576, type: 'image/jpeg', uploadedAt: '2023-01-16T14:22:00Z' },
    { id: 'file3', name: 'video.mp4', size: 104857600, type: 'video/mp4', uploadedAt: '2023-01-17T09:15:00Z' },
    { id: 'file4', name: 'planilha.xlsx', size: 512000, type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', uploadedAt: '2023-01-18T16:45:00Z' }
  ];

  res.json({ files });
});

// Rota raiz
app.get('/', (req, res) => {
  res.json({ message: 'API do Cloudim - Backend de Autenticação e Contas (Versão Simplificada)' });
});

// Tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo deu errado!' });
});

// Middleware para rotas não encontradas
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor do Cloudim (versão simplificada) rodando na porta ${PORT}`);
  console.log(`Endpoints disponíveis:`);
  console.log(`POST /api/auth/register - Registrar novo usuário`);
  console.log(`POST /api/auth/login - Fazer login`);
  console.log(`GET /api/auth/verify - Verificar token`);
  console.log(`GET /api/user/profile - Obter perfil do usuário`);
  console.log(`PUT /api/user/profile - Atualizar perfil do usuário`);
  console.log(`GET /api/user/stats - Obter estatísticas do usuário`);
  console.log(`POST /api/files/upload - Upload de arquivo`);
  console.log(`GET /api/files - Listar arquivos`);
  console.log(`\nOs dados dos usuários são armazenados no arquivo users.json`);
});