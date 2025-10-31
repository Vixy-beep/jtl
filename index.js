// api/index.js - Backend para Vercel
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

// 3. Conectar a la Base de Datos (Vercel usará estas variables)
const MONGO_URL = process.env.MONGO_URL || "mongodb+srv://<REEMPLAZAR_USUARIO>:<REEMPLAZAR_CONTRASEÑA>@jtl-tienda-cluster.zc83gfl.mongodb.net/tiendaDB?appName=jtl-tienda-cluster";
const JWT_SECRET = process.env.JWT_SECRET || 'tu-llave-secreta-super-dificil-de-adivinar-12345';

mongoose.connect(MONGO_URL)
  .then(() => {
    console.log('¡Conectado a MongoDB Atlas! (Vercel)');
  })
  .catch((err) => {
    console.error('Error al conectar a MongoDB:', err);
  });

// 4. Modelos de la Base de Datos (Mongoose)
// (Asegúrate de que esta estructura coincida con tu base de datos)
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


// 5. Seguridad: Middleware de Autenticación (JWT)
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


// 6. RUTAS DE LA API (Endpoints)

// RUTA BASE (Para verificar que Vercel funciona)
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


// ... [Otras rutas de Admin JTL: /api/stores, /api/stores/pay, etc.] ...
// (Para un despliegue rápido, estas no son esenciales ahora mismo, pero se añadirían aquí)


// 7. Exportar para Vercel
module.exports = app;
