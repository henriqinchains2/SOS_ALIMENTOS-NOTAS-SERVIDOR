require("dotenv").config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require("multer");
const streamifier = require("streamifier");
const cloudinary = require('cloudinary').v2;
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();

app.use(express.json());

//ACORDA
app.get("/health", (req, res) => {
    res.status(200).send("OK");
});

mongoose
    .connect(process.env.MONGO_URL, { family: 4 })
    .then(() => console.log("✅ Conectado ao MongoDB com sucesso!"))
    .catch((err) => console.log("❌ Erro ao conectar no banco:", err));

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: {
        fileSize: 11 * 1024 * 1024 // 11 MB
    }
});

function uploadParaCloudinary(buffer) {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            { folder: "notas_fiscais" },
            (error, result) => {
                if (error) return reject(error);
                resolve(result);
            }
        );
        streamifier.createReadStream(buffer).pipe(stream);
    });
}

const allowedOrigins = [
    "https://henriqinchains.github.io",
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
];

app.set("trust proxy", 1);

app.use(
    cors({
        origin: function (origin, callback) {
            if (!origin) return callback(null, true);
            const isAllowed = allowedOrigins.some((allowedUrl) => origin.startsWith(allowedUrl));
            if (isAllowed) {
                callback(null, true);
            } else {
                callback(new Error("Bloqueado pelo CORS do SOS ALIMENTOS!"));
            }
        },
        credentials: true,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"],
    })
);

app.use(cookieParser());

// Configuração central do cookie de sessão, usada tanto no login quanto no
// cadastro — precisa ser IDÊNTICA nos dois, senão quem se cadastra pela
// primeira vez recebe um cookie que não funciona no cenário cross-site
// (frontend no GitHub Pages, API no Render).
const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    partitioned: true,
    maxAge: 30 * 24 * 60 * 60 * 1000
};

// ==================== MIDDLEWARES DE AUTENTICAÇÃO ====================

// Verifica se existe um token válido e anexa os dados do usuário em req.usuario
function verificarLogin(req, res, next) {
    const token = req.cookies.authToken;

    if (!token) {
        return res.status(401).json({
            erro: "Acesso negado. Faça login novamente."
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.usuario = decoded;
        next();
    } catch (erro) {
        return res.status(401).json({
            erro: "Sessão inválida ou expirada. Faça login novamente."
        });
    }
}

// Deve ser usado sempre DEPOIS de verificarLogin.
// Recebe a lista de cargos permitidos, ex: verificarCargo("admin", "financeiro")
function verificarCargo(...cargosPermitidos) {
    return (req, res, next) => {
        if (!cargosPermitidos.includes(req.usuario.cargo)) {
            return res.status(403).json({ erro: "Você não tem permissão para acessar este recurso." });
        }
        next();
    };
}

// ==================== MODELOS ====================

//modelo cliente
const ClienteSchema = new mongoose.Schema({
    cliente: { type: String, required: true, unique: true },
    email: { type: String, required: false, unique: true, sparse: true, lowercase: true, trim: true },
    cnpj: { type: String, required: false },
    telefone: { type: String, required: false },
    endereco: { type: String, required: true },
    bairro: { type: String, required: true },
    complemento: { type: String, required: false },
}, { timestamps: true });

const Cliente = mongoose.model("Cliente", ClienteSchema, "clientes");

//modelo nota fiscal
const NotasFiscaisSchema = new mongoose.Schema({
    idCliente: { type: String, required: true },
    cliente: { type: String, required: true },
    numeroNota: { type: String, required: true },

    valor: { type: Number, required: true },
    dataEmissao: { type: Date, required: true },
    entregadorId: { type: mongoose.Schema.Types.ObjectId, ref: "Usuario", required: true },
    entregador: { type: String, required: true },
    pago: { type: Boolean, required: true, default: false },
    enviado: { type: Boolean, required: true, default: false },

    deletado: { type: Boolean, required: true, default: false },
    deletadoEm: { type: Date, required: false },

    img: { type: String, required: false },
    imgPublicId: { type: String, required: false },

}, { timestamps: true });

const NotasFiscais = mongoose.model("notas", NotasFiscaisSchema, "notas_fiscais");

//modelo grupo notas
const GrupoNotasSchema = new mongoose.Schema({
    observacao: { type: String, required: false },
    idCliente: { type: String, required: true },
    notasId: [{ type: mongoose.Schema.Types.ObjectId, ref: 'NotasFiscais' }],

    dataCriacao: { type: Date, default: Date.now },

    dataExclusao: { type: Date, required: false },
    dataAtualizacao: { type: Date, default: Date.now },

}, { timestamps: true });

const GrupoNotas = mongoose.model("GrupoNotas", GrupoNotasSchema, "grupos_notas");

//modelo usuarios
const UsuarioSchema = new mongoose.Schema({
    nome: { type: String, required: true, unique: true },
    telefone: { type: String, required: true, unique: true },
    senha: { type: String, required: true },
    cargo: { type: String, enum: ["entregador", "financeiro", "admin"], default: "entregador" },
}, { timestamps: true });

const Usuario = mongoose.model("Usuario", UsuarioSchema, "usuarios");

function normalizarNotaComEntregador(nota) {
    const documento = nota && typeof nota.toObject === "function" ? nota.toObject() : { ...nota };
    const nomeDoEntregador = documento.entregadorId && typeof documento.entregadorId === "object"
        ? documento.entregadorId.nome
        : documento.entregador;

    return {
        ...documento,
        entregador: nomeDoEntregador || documento.entregador || ""
    };
}

// ==================== AUTENTICAÇÃO ====================

//cadastro
app.post("/api/auth/cadastro", async (req, res) => {
    try {
        const { nome, telefone, password } = req.body;

        if (!nome || !telefone || !password) {
            return res.status(400).json({ erro: "Por favor, preencha todos os campos." });
        }

        // Validação do telefone (aceita com ou sem parênteses/traço/espaço)
        const telefoneRegex = /^\s*\(?(\d{2})?\)?[-. ]?(\d{4,5})[-. ]?(\d{4})\s*$/;

        if (!telefoneRegex.test(telefone)) {
            return res.status(400).json({ erro: "Telefone inválido." });
        }

        // Remove tudo que não for número antes de salvar
        const telefoneLimpo = telefone.replace(/\D/g, "");

        const usuarioExiste = await Usuario.findOne({
            $or: [
                { nome },
                { telefone: telefoneLimpo }
            ]
        });

        if (usuarioExiste) {
            if (usuarioExiste.nome === nome) {
                return res.status(400).json({
                    erro: "Este nome de usuário já está sendo usado."
                });
            }

            return res.status(400).json({
                erro: "Este telefone já está cadastrado."
            });
        }

        const salt = await bcrypt.genSalt(10);
        const senhaCriptografada = await bcrypt.hash(password, salt);

        const novoUsuario = new Usuario({
            nome,
            telefone: telefoneLimpo,
            senha: senhaCriptografada
        });

        await novoUsuario.save();

        const token = jwt.sign(
            {
                id: novoUsuario._id,
                nome: novoUsuario.nome,
                cargo: novoUsuario.cargo
            },
            process.env.JWT_SECRET,
            { expiresIn: "30d" }
        );

        // CORREÇÃO: usa a mesma config de cookie do login (antes estava com
        // sameSite:"lax" e sem partitioned, o que quebra no cenário cross-site)
        res.cookie("authToken", token, COOKIE_OPTIONS);

        return res.status(201).json({
            mensagem: "Usuário cadastrado com sucesso!",
            nome: novoUsuario.nome,
            usuario: {
                id: novoUsuario._id,
                nome: novoUsuario.nome
            }
        });

    } catch (erro) {
        console.error("❌ Erro no cadastro:", erro);
        return res.status(500).json({
            erro: "Erro ao tentar cadastrar usuário."
        });
    }
});

//LOGIN
app.post("/api/auth/login", async (req, res) => {
    try {
        const { login, password } = req.body;

        if (!login || !password) {
            return res.status(400).json({ erro: "Preencha usuário/telefone e senha." });
        }

        const telefone = login.replace(/\D/g, "");

        const usuarioEncontrado = await Usuario.findOne({
            $or: [
                { nome: login },
                { telefone }
            ]
        });

        if (!usuarioEncontrado) return res.status(400).json({ erro: "Usuário ou senha incorretos." });

        const senhaValidaLogin = await bcrypt.compare(password, usuarioEncontrado.senha);
        if (!senhaValidaLogin) return res.status(400).json({ erro: "Usuário ou senha incorretos." });

        const token = jwt.sign(
            { id: usuarioEncontrado._id, nome: usuarioEncontrado.nome, cargo: usuarioEncontrado.cargo },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.cookie("authToken", token, COOKIE_OPTIONS);

        return res.status(200).json({
            mensagem: "Login realizado com sucesso!",
            login: usuarioEncontrado.nome,
            cargo: usuarioEncontrado.cargo,
        });

    } catch (erro) {
        console.error("❌ Erro no login:", erro);
        return res.status(500).json({ erro: "Erro ao tentar fazer login." });
    }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
    res.cookie("authToken", "", {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        partitioned: true,
        expires: new Date(0)
    });
    return res.status(200).json({ mensagem: "Deslogado com sucesso!" });
});

// Validação de Sessão (/me)
app.get("/api/auth/me", verificarLogin, async (req, res) => {
    try {
        const userDb = await Usuario.findById(req.usuario.id);
        if (!userDb) return res.status(401).json({ logado: false });

        return res.json({
            logado: true,
            login: req.usuario.nome,
            cargo: req.usuario.cargo || "entregador",
            id: req.usuario.id,
        });
    } catch (err) {
        return res.status(401).json({ logado: false });
    }
});

// ==================== USUÁRIOS / ENTREGADORES ====================

app.get("/api/usuarios/entregadores", verificarLogin, verificarCargo("financeiro", "admin"), async (req, res) => {
    try {
        const entregadores = await Usuario.find(
            { cargo: "entregador" },
            { _id: 1, nome: 1 }
        ).sort({ nome: 1 });

        res.json(entregadores);
    } catch (erro) {
        console.error("Erro ao buscar entregadores:", erro);
        res.status(500).json({
            erro: "Erro ao buscar entregadores."
        });
    }
});

// ==================== CLIENTES ====================

//criar cliente
app.post('/api/clientes', verificarLogin, async (req, res) => {
    try {
        const { cliente, email, cnpj, telefone, endereco, complemento, bairro } = req.body;

        const clienteExistente = await Cliente.findOne({ cliente });
        if (clienteExistente) {
            return res.status(400).json({ error: "Cliente com este nome já cadastrado." });
        }

        const novoCliente = new Cliente({ cliente, email, cnpj, telefone, endereco, complemento, bairro });

        await novoCliente.save();

        res.status(201).json(novoCliente);

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

// Importação em lote de clientes via CSV (usado pelo botão "Importar clientes
// via CSV" no modal de cadastro). Processa um por um em vez de usar
// insertMany, pra um cliente com problema não derrubar o lote inteiro — cada
// linha entra ou é ignorada individualmente, e a resposta lista os dois casos.
app.post('/api/clientes/importar-lote', verificarLogin, async (req, res) => {
    try {
        const { clientes } = req.body;

        if (!Array.isArray(clientes) || clientes.length === 0) {
            return res.status(400).json({ erro: "Nenhum cliente enviado para importação." });
        }

        const resultado = {
            importados: 0,
            ignorados: [] // { cliente, motivo }
        };

        for (const dadosCliente of clientes) {
            const { cliente, email, cnpj, telefone, endereco, complemento, bairro } = dadosCliente || {};

            if (!cliente || !endereco || !bairro) {
                resultado.ignorados.push({
                    cliente: cliente || "(sem nome)",
                    motivo: "Faltam campos obrigatórios (nome, endereço ou bairro)."
                });
                continue;
            }

            try {
                const clienteExistente = await Cliente.findOne({ cliente });
                if (clienteExistente) {
                    resultado.ignorados.push({ cliente, motivo: "Já existe um cliente com este nome." });
                    continue;
                }

                const novoCliente = new Cliente({
                    cliente,
                    // string vazia "" não é ignorada pelo índice único+sparse do
                    // email (só null/undefined são) — undefined evita erro de
                    // duplicata quando vários clientes do CSV não têm e-mail
                    email: email || undefined,
                    cnpj,
                    telefone,
                    endereco,
                    complemento,
                    bairro
                });

                await novoCliente.save();
                resultado.importados++;

            } catch (erroIndividual) {
                console.error(`Erro ao importar cliente "${cliente}":`, erroIndividual.message);
                resultado.ignorados.push({ cliente, motivo: "Erro ao salvar: " + erroIndividual.message });
            }
        }

        res.status(201).json(resultado);

    } catch (erro) {
        console.error("Erro na importação em lote:", erro);
        res.status(500).json({ erro: "Erro ao importar clientes." });
    }
});

//carregar cliente
app.get('/api/clientes', verificarLogin, async (req, res) => {
    try {
        const clientes = await Cliente.find();
        res.json(clientes);
    } catch (error) {
        res.status(500).json({ error: "Erro ao buscar clientes." });
    }
});

// ==================== NOTAS FISCAIS ====================

//criar nota fiscal
app.post('/api/notas', verificarLogin, upload.single('img'), async (req, res) => {
    try {
        const body = req.body || {};
        const usuarioAutenticado = req.usuario;
        const podeAtribuirEntregador = ["admin", "financeiro"].includes(usuarioAutenticado.cargo);

        let entregadorSelecionado = null;
        let entregadorIdParaSalvar = null;

        const rawEntregadorId = body.entregadorId || (() => {
            if (typeof body.entregador_obj !== "string") return null;

            try {
                const entregadorObj = JSON.parse(body.entregador_obj);
                return entregadorObj && entregadorObj._id ? entregadorObj._id : null;
            } catch (erro) {
                return null;
            }
        })();

        if (rawEntregadorId) {
            const idInformado = String(rawEntregadorId);
            const ehOProprioUsuario = idInformado === String(usuarioAutenticado.id);

            // Só bloqueia quando o usuário está tentando atribuir a nota a OUTRO
            // entregador. Um entregador enviando o próprio id (como faz o
            // entrega.html) é sempre permitido.
            if (!podeAtribuirEntregador && !ehOProprioUsuario) {
                return res.status(403).json({ erro: "Você não tem permissão para atribuir um entregador diferente." });
            }

            if (!mongoose.Types.ObjectId.isValid(idInformado)) {
                return res.status(400).json({ erro: "Identificador do entregador inválido." });
            }

            entregadorSelecionado = await Usuario.findById(idInformado).select("_id nome cargo");
            if (!entregadorSelecionado) {
                return res.status(400).json({ erro: "Entregador não encontrado." });
            }

            if (entregadorSelecionado.cargo !== "entregador") {
                return res.status(400).json({ erro: "O usuário informado não é um entregador válido." });
            }

            entregadorIdParaSalvar = entregadorSelecionado._id;
        } else {
            entregadorSelecionado = await Usuario.findById(usuarioAutenticado.id).select("_id nome cargo");
            if (!entregadorSelecionado) {
                return res.status(401).json({ erro: "Usuário do entregador não encontrado." });
            }

            entregadorIdParaSalvar = entregadorSelecionado._id;
        }

        let publicId = "";
        let linkDaFotoNuvem = "";

        if (req.file) {
            console.log("Subindo foto da nota para o Cloudinary...");

            const resultado = await uploadParaCloudinary(req.file.buffer);

            linkDaFotoNuvem = resultado.secure_url;
            publicId = resultado.public_id;

            console.log("Foto da nota enviada para o Cloudinary com sucesso.", linkDaFotoNuvem);
        }

        const nomeDoEntregador = entregadorSelecionado.nome;

        const novaNota = new NotasFiscais({
            idCliente: body.idCliente,
            cliente: body.cliente,
            numeroNota: body.numeroNota,
            valor: body.valor,
            dataEmissao: body.dataEmissao,
            entregadorId: entregadorIdParaSalvar,
            entregador: nomeDoEntregador,
            pago: body.pago ?? false,
            enviado: body.enviado ?? false,
            img: linkDaFotoNuvem || body.img || "",
            imgPublicId: publicId || body.imgPublicId || ""
        });

        await novaNota.save();
        res.status(201).json(novaNota);
    } catch (erro) {
        console.error("Erro ao criar nota fiscal:", erro);
        res.status(500).json({ error: "Erro ao criar nota fiscal." });
    }
});

// listar notas da lixeira (excluídas, mas ainda no banco)
// IMPORTANTE: precisa vir ANTES de qualquer rota GET "/api/notas/:id" que
// venha a existir no futuro, senão "lixeira" seria interpretado como um :id
app.get('/api/notas/lixeira', verificarLogin, async (req, res) => {
    try {
        const notas = await NotasFiscais.find({ deletado: true }).populate("entregadorId", "nome");
        res.json(notas.map(normalizarNotaComEntregador));
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ error: "Erro ao buscar notas da lixeira." });
    }
});

// conta quantas notas ativas um cliente já tem (usado só pra numerar a próxima nota).
// Liberado pra qualquer usuário logado (inclusive entregador), diferente do
// GET /api/notas completo, que expõe valores e status de pagamento de todos os clientes.
app.get('/api/notas/contagem/:idCliente', verificarLogin, async (req, res) => {
    try {
        const quantidade = await NotasFiscais.countDocuments({
            idCliente: req.params.idCliente,
            deletado: false
        });
        res.json({ quantidade });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ error: "Erro ao contar notas do cliente." });
    }
});

// carregar notas ativas
app.get('/api/notas', verificarLogin, verificarCargo("financeiro", "admin"), async (req, res) => {
    try {
        const notas = await NotasFiscais.find({ deletado: false }).populate("entregadorId", "nome");
        res.json(notas.map(normalizarNotaComEntregador));
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Erro ao buscar notas." });
    }
});

//deletar notas (soft delete: vai pra lixeira)
app.delete('/api/notas/:id', verificarLogin, verificarCargo("financeiro", "admin"), async (req, res) => {
    try {
        const nota = await NotasFiscais.findById(req.params.id);

        if (!nota) {
            return res.status(404).json({ error: "Nota fiscal não encontrada." });
        }

        nota.deletado = true;
        nota.deletadoEm = new Date();

        await nota.save();

        res.status(200).json({ message: "Nota fiscal deletada com sucesso.", nota });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Erro ao deletar nota fiscal." });
    }
});

// excluir definitivamente (remove do banco) a partir da Lixeira
app.delete('/api/notas/:id/permanente', verificarLogin, verificarCargo("admin"), async (req, res) => {
    try {
        const nota = await NotasFiscais.findByIdAndDelete(req.params.id);

        if (!nota) {
            return res.status(404).json({ error: "Nota não encontrada." });
        }

        if (nota.imgPublicId) {
            await cloudinary.uploader.destroy(nota.imgPublicId);
        }

        // remove a referência dessa nota de qualquer grupo que a contenha,
        // evitando ids "fantasma" sobrando no notasId dos grupos
        await GrupoNotas.updateMany(
            { notasId: req.params.id },
            { $pull: { notasId: req.params.id } }
        );

        res.json({ ok: true });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ error: "Erro ao excluir nota permanentemente." });
    }
});

//restaurar nota (tira da lixeira)
app.put('/api/notas/:id/restaurar', verificarLogin, verificarCargo("admin", "financeiro"), async (req, res) => {
    try {
        const nota = await NotasFiscais.findByIdAndUpdate(
            req.params.id,
            {
                deletado: false,
                deletadoEm: null
            },
            { new: true }
        );

        if (!nota) {
            return res.status(404).json({ error: "Nota não encontrada." });
        }

        res.json(nota);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ error: "Erro ao restaurar nota." });
    }
});

//atualizar status pagamento nota
app.put("/api/notas/:id/pago", verificarLogin, verificarCargo("admin", "financeiro"), async (req, res) => {
    try {
        const nota = await NotasFiscais.findById(req.params.id);

        if (!nota) {
            return res.status(404).json({ erro: "Nota não encontrada." });
        }

        nota.pago = !nota.pago;
        await nota.save();

        res.json(nota);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao atualizar nota." });
    }
});

// ==================== GRUPOS DE NOTAS ====================

//criar grupo de notas
app.post("/api/grupos", verificarLogin, verificarCargo("admin", "financeiro"), async (req, res) => {
    try {
        const { observacao, idCliente, notasId } = req.body;

        const novoGrupo = new GrupoNotas({
            observacao,
            idCliente,
            notasId,
        });
        await novoGrupo.save();
        res.status(201).json(novoGrupo);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Erro ao criar grupo de notas." });
    }
});

// carregar grupos de notas, menos os excluídos
app.get("/api/grupos", verificarLogin, verificarCargo("admin", "financeiro"), async (req, res) => {
    try {
        const { idCliente } = req.query;
        const filtro = { dataExclusao: null };
        if (idCliente) filtro.idCliente = idCliente;

        const grupos = await GrupoNotas.find(filtro);
        res.json(grupos);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ error: "Erro ao buscar grupos." });
    }
});

// Editar grupo (observação/notas)
app.put("/api/grupos/:id", verificarLogin, verificarCargo("admin", "financeiro"), async (req, res) => {
    try {
        const grupoAtualizado = await GrupoNotas.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );

        if (!grupoAtualizado) {
            return res.status(404).json({ error: "Grupo não encontrado." });
        }

        res.json(grupoAtualizado);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ error: "Erro ao atualizar grupo." });
    }
});

// excluir grupo - marca grupo e notas como excluídas
app.delete("/api/grupos/:id", verificarLogin, verificarCargo("admin", "financeiro"), async (req, res) => {
    try {
        const grupo = await GrupoNotas.findById(req.params.id);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado." });
        }

        const agora = new Date();

        //marca o grupo como excluído (campo do schema de GrupoNotas)
        grupo.dataExclusao = agora;
        await grupo.save();

        //marca todas as notas do grupo como excluídas também
        await NotasFiscais.updateMany(
            { _id: { $in: grupo.notasId } },
            { $set: { deletado: true, deletadoEm: agora } }
        );

        res.json({ ok: true, grupo });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ error: "Erro ao excluir grupo." });
    }
});

//CRIAÇÃO DA TABELA E MANIPULAÇÃO DA MESMA
const RotaPlanejadaSchema = new mongoose.Schema({
    data: { type: String, required: true },

    entregadorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Usuario",
        required: false
    },

    entregador: {
        type: String,
        required: true
    },

    clientes: [{
        type: String,
        required: true
    }],

}, { timestamps: true });

RotaPlanejadaSchema.index(
    { data: 1, entregador: 1 },
    { unique: true }
);

const RotaPlanejada = mongoose.model("RotaPlanejada", RotaPlanejadaSchema, "rotas_planejadas");

app.get('/api/rotas-planejadas', verificarLogin, async (req, res) => {
    try {
        const { data } = req.query;
        const rotas = await RotaPlanejada.find(data ? { data } : {});
        res.json(rotas);
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao buscar rotas planejadas." });
    }
});

app.post('/api/rotas-planejadas', verificarLogin, verificarCargo("admin"), async (req, res) => {
    try {
        const { data, rotas } = req.body;
        if (!data || !Array.isArray(rotas)) {
            return res.status(400).json({ erro: "Dados inválidos." });
        }

        await RotaPlanejada.deleteMany({ data }); // substitui o planejamento do dia inteiro

        const documentos = rotas
            .filter(r => r.entregador && Array.isArray(r.clientes) && r.clientes.length > 0)
            .map(r => ({
    data,
    entregadorId: r.entregadorId || null,
    entregador: r.entregador,
    clientes: r.clientes
}));

        if (documentos.length > 0) await RotaPlanejada.insertMany(documentos);

        res.status(201).json({ mensagem: "Rotas planejadas salvas.", quantidade: documentos.length });
    } catch (erro) {
        console.error(erro);
        res.status(500).json({ erro: "Erro ao salvar rotas planejadas." });
    }
});

// ==================== UTIL ====================

// Extrai o public_id do Cloudinary a partir da URL da imagem.
// Função pura, sem lógica de autenticação (a auth já é feita nas rotas que a chamam).
function obterPublicIdDaUrl(url) {
    if (!url) return null;
    const partes = url.split('/');
    const arquivoComExtensao = partes.pop();
    const pasta = partes.pop();
    const arquivoSemExtensao = arquivoComExtensao.split('.')[0];
    return `${pasta}/${arquivoSemExtensao}`;
}

//iniciar servidor
const PORTA = process.env.PORT || 3000;
app.listen(PORTA, () => {
    console.log(`🚀 Servidor rodando na porta ${PORTA}`);
});
