// api/index.js - Backend para Render (Configuración Final)
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 1. Constantes de Negocio
const COMMISSION_PERCENT = 5; // 5% global
const SUBSCRIPTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 días

// 2. Inicializar y Configurar Express
const app = express();
app.use(cors()); 
app.use(express.json()); 

// 3. Conexión a la Base de Datos y Variables
const MONGO_URL = process.env.MONGO_URL || "mongodb+srv://jtl_admin1:jw4OxrvWN0X9nbzH@jtl-tienda-cluster.zc83gfl.mongodb.net/tiendaDB";
const JWT_SECRET = process.env.JWT_SECRET || 'tu-llave-secreta-super-dificil-de-adivinar-12345';

// 4. Conexión de Mongoose (Simple y Robusta para Hosting)
mongoose.connect(MONGO_URL, { 
    serverSelectionTimeoutMS: 5000, 
    family: 4 
})
.then(() => {
    console.log('¡Conectado a MongoDB Atlas!');
})
.catch((err) => {
    console.error('Error al conectar a MongoDB:', err);
});

// 5. Modelos de la Base de Datos (Mongoose)
const storeSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  whatsapp: { type: String },
  password: { type: String, required: true },
  isPublic: { type: Boolean, default: true },
  subscriptionPaidUntil: { type: Date },
  blocked: { type: Boolean, default: false },
  totalRevenue: { type: Number, default: 0 },
  platformFeeOwed: { type: Number, default: 0 }
});
const Store = mongoose.model('Store', storeSchema);

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, default: 'General' },
  price: { type: Number, required: true, min: 0 },
  stock: { type: Number, default: 0, min: 0 },
  img: { type: String },
  store: { type: mongoose.Schema.Types.ObjectId, ref: 'Store', required: true }
});
const Product = mongoose.model('Product', productSchema);


// 6. Seguridad: Middleware de Autenticación (JWT)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.status(401).json({ message: 'No estás autorizado' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

const authenticateAdmin = (req, res, next) => {
  if (req.user.name !== 'jtl') {
    return res.status(403).json({ message: 'No tienes permisos de administrador' });
  }
  next();
};


// 7. RUTAS DE LA API (Endpoints)

// RUTA BASE (Para verificar que Express está cargado)
app.get('/', (req, res) => {
    res.send('API de Tienda JTL funcionando. Usa /api/stores o /api/products');
});

// RUTA GET: OBTENER TODAS LAS TIENDAS (PÚBLICA)
app.get('/api/stores', async (req, res) => {
  try {
    const stores = await Store.find({}, 'name isPublic whatsapp subscriptionPaidUntil');
    res.json(stores);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener tiendas' });
  }
});

// RUTA POST: REGISTRAR TIENDA (PÚBLICA)
app.post('/api/stores/register', async (req, res) => {
  try {
    const { name, password, whatsapp } = req.body;
    const existingStore = await Store.findOne({ name: name });
    if (existingStore) {
      return res.status(400).json({ message: 'Ya existe una tienda con ese nombre' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newStore = new Store({
      name: name,
      password: hashedPassword,
      whatsapp: whatsapp || '',
      subscriptionPaidUntil: new Date(Date.now() + SUBSCRIPTION_MS) // +30 días gratis
    });
    await newStore.save();
    console.log('¡Tienda registrada con éxito:', newStore.name);
    res.status(201).json({ message: 'Tienda registrada con éxito', storeId: newStore._id });

  } catch (error) {
    console.error('Error al registrar tienda:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// RUTA POST: LOGIN DE TIENDA (PÚBLICA)
app.post('/api/stores/login', async (req, res) => {
  try {
    const { storeId, password } = req.body;
    const store = await Store.findById(storeId);
    if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });
    const isMatch = await bcrypt.compare(password, store.password);
    if (!isMatch) return res.status(400).json({ message: 'Contraseña incorrecta' });

    const token = jwt.sign(
      { storeId: store._id, name: store.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.status(200).json({ message: 'Login exitoso', token: token, store: store });
  } catch (error) {
    res.status(500).json({ message: 'Error en el login' });
  }
});

// RUTA GET: OBTENER PRODUCTOS DE UNA TIENDA (PÚBLICA)
app.get('/api/products/:storeId', async (req, res) => {
  try {
    const store = await Store.findById(req.params.storeId);
    if (!store) return res.json([]);
    const products = await Product.find({ store: store._id });
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Error buscando productos' });
  }
});

// RUTA POST: CREAR PRODUCTO (PRIVADA)
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, category, price, stock, img } = req.body;
    if (!name || !price) return res.status(400).json({ message: 'Nombre y precio son requeridos' });
    
    const newProduct = new Product({
      name: name, category: category || 'General', price: Number(price), stock: Number(stock) || 0,
      img: img || '', store: req.user.storeId 
    });
    await newProduct.save();
    res.status(201).json({ message: 'Producto guardado con éxito', product: newProduct });
  } catch (error) {
    res.status(500).json({ message: 'Error al guardar producto' });
  }
});

// RUTA DELETE: BORRAR UN PRODUCTO (PRIVADA)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    if (product.store.toString() !== req.user.storeId) return res.status(403).json({ message: 'No tienes permiso para borrar este producto' });
    
    await Product.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'Producto eliminado con éxito' });
  } catch (error) {
    res.status(500).json({ message: 'Error al eliminar producto' });
  }
});

// RUTA POST: VENTA EN EFECTIVO (PRIVADA)
app.post('/api/sales/cash', authenticateToken, async (req, res) => {
  try {
    const { productId, quantity, paidAmount } = req.body;
    const qty = Number(quantity);
    if (qty <= 0) return res.status(400).json({ message: 'Cantidad inválida' });

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    if (product.store.toString() !== req.user.storeId) return res.status(403).json({ message: 'Producto no pertenece a tu tienda' });
    if (product.stock < qty) return res.status(400).json({ message: `Stock insuficiente. Solo quedan ${product.stock}` });
    
    const total = product.price * qty;
    const change = Number(paidAmount) - total;
    if (change < 0) return res.status(400).json({ message: 'El monto recibido no cubre el total' });
    
    const commission = total * (COMMISSION_PERCENT / 100);

    // Actualizar BD
    product.stock -= qty;
    await product.save();
    
    const updatedStore = await Store.findByIdAndUpdate(req.user.storeId, {
      $inc: { totalRevenue: total, platformFeeOwed: commission }
    }, { new: true }); 

    res.status(200).json({
      message: `Venta registrada — Cambio: RD$${change.toFixed(2)}`,
      newStats: { totalRevenue: updatedStore.totalRevenue, platformFeeOwed: updatedStore.platformFeeOwed }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error en Venta en Efectivo' });
  }
});

// RUTA GET: OBTENER ESTADÍSTICAS (PRIVADA)
app.get('/api/stats/:storeId', authenticateToken, async (req, res) => {
  try {
    const store = await Store.findById(req.params.storeId, 'totalRevenue platformFeeOwed name subscriptionPaidUntil whatsapp');
    if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });
    
    // Seguridad: Solo JTL o el dueño de la tienda pueden ver estas stats
    if (req.user.storeId !== req.params.storeId && req.user.name !== 'jtl') {
        return res.status(403).json({ message: 'No tienes permiso para ver estas estadísticas' });
    }
    
    res.status(200).json(store);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener stats' });
  }
});


// 8. Exportar la aplicación Express para el hosting
// --- AL FINAL DEL ARCHIVO api/index.js ---

// 1. Exporta la aplicación para la ruta Serverless (¡si el hosting lo necesita!)
//    Esto es lo que hace que Express funcione en Render/Vercel
module.exports = app;

// 2. Bloque de Listen para que Render o Vercel lo inicien correctamente
//    Esto es lo que Render necesita para detectar un puerto activo.
const port_render = process.env.PORT || 3000; 
    
// Añadimos '0.0.0.0' para que Express se enlace a la IP de la máquina de hosting
app.listen(port_render, '0.0.0.0', () => { 
    console.log(`Servidor de Express escuchando en el puerto ${port_render}`); 
});

