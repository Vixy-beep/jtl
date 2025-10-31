// api/index.js - Backend COMPLETO para Render
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 1. Constantes de Negocio
const COMMISSION_PERCENT = 5; // 5% global
const SUBSCRIPTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 días
const DEFAULT_MONTHLY_AMOUNT = 500;

// 2. Inicializar y Configurar Express
const app = express();

// --- ¡ESTA ES LA CORRECCIÓN DE CORS! ---
// Le decimos explícitamente que acepte peticiones de tu sitio Netlify
const corsOptions = {
  origin: 'https://softwarejtl.netlify.app',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  allowedHeaders: 'Content-Type,Authorization'
};
app.use(cors(corsOptions));
// --- FIN DE LA CORRECCIÓN ---

app.use(express.json()); 

// 3. Conexión a la Base de Datos y Variables
const MONGO_URL = process.env.MONGO_URL || "mongodb+srv://jtl_admin1:jw4OxrvWN0X9nbzH@jtl-tienda-cluster.zc83gfl.mongodb.net/tiendaDB";
const JWT_SECRET = process.env.JWT_SECRET || 'tu-llave-secreta-super-dificil-de-adivinar-12345';

// 4. Conexión de Mongoose (Simple y Robusta)
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

const settingSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: { type: mongoose.Schema.Types.Mixed }
});
const Setting = mongoose.model('Setting', settingSchema);


// 6. Seguridad: Middlewares
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.status(401).json({ message: 'No estás autorizado' });

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    
    const store = await Store.findById(user.storeId);
    if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });
    
    if (store.name !== 'jtl') {
      const isSubActive = store.subscriptionPaidUntil && store.subscriptionPaidUntil.getTime() >= Date.now();
      if (!isSubActive) {
        return res.status(403).json({ message: 'Suscripción vencida. Contacta a JTL.' });
      }
    }
    req.user = user;
    next();
  });
};

const authenticateAdmin = (req, res, next) => {
  if (req.user.name !== 'jtl') {
    return res.status(403).json({ message: 'No tienes permisos de administrador (JTL)' });
  }
  next();
};


// 7. RUTAS DE LA API (Endpoints)

app.get('/api/stores', async (req, res) => {
  try {
    const stores = await Store.find({}, 'name isPublic whatsapp subscriptionPaidUntil _id'); // Asegúrate de incluir _id
    res.json(stores);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener tiendas' });
  }
});

app.post('/api/stores/login', async (req, res) => {
  try {
    const { storeId, password } = req.body;
    const store = await Store.findById(storeId);
    if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });

    if (store.name !== 'jtl') {
      const isSubActive = store.subscriptionPaidUntil && store.subscriptionPaidUntil.getTime() >= Date.now();
      if (!isSubActive) {
        return res.status(403).json({ message: 'Suscripción vencida. Contacta a JTL.' });
      }
    }

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

app.post('/api/sales/whatsapp', async (req, res) => {
    try {
        const { cart, storeId } = req.body;
        if (!cart || !storeId) return res.status(400).json({ message: 'Faltan datos' });

        const store = await Store.findById(storeId);
        if (store.name !== 'jtl') {
          const isSubActive = store.subscriptionPaidUntil && store.subscriptionPaidUntil.getTime() >= Date.now();
          if (!isSubActive) return res.status(403).json({ message: 'Suscripción vencida. No se pueden procesar pedidos.' });
        }

        let totalSale = 0;
        let totalCommission = 0;
        let stockErrors = [];
        const operations = [];

        for (const item of cart) {
            const product = await Product.findById(item.productId);
            if (!product) {
                stockErrors.push(`Producto ID ${item.productId} no encontrado.`);
                continue;
            }
            if (product.store.toString() !== storeId) {
                stockErrors.push(`Producto ${product.name} no pertenece a esta tienda.`);
                continue;
            }
            if (product.stock < item.qty) {
                stockErrors.push(`Stock insuficiente para ${product.name}. Solo quedan ${product.stock}.`);
                continue;
            }

            const total = product.price * item.qty;
            totalSale += total;
            totalCommission += total * (COMMISSION_PERCENT / 100);

            product.stock -= item.qty;
            operations.push(product.save());
        }

        if (stockErrors.length > 0) {
            return res.status(400).json({ message: 'Error de stock: ' + stockErrors.join(', ') });
        }

        await Promise.all(operations);
        await Store.findByIdAndUpdate(storeId, {
            $inc: { totalRevenue: totalSale, platformFeeOwed: totalCommission }
        });

        res.status(200).json({ message: 'Venta registrada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error en Venta WhatsApp' });
    }
});

app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, category, price, stock, img } = req.body;
    if (!name || !price) return res.status(400).json({ message: 'Nombre y precio son requeridos' });
    const newProduct = new Product({
      name, category: category || 'General', price: Number(price), stock: Number(stock) || 0,
      img: img || '', store: req.user.storeId 
    });
    await newProduct.save();
    res.status(201).json({ message: 'Producto guardado con éxito', product: newProduct });
  } catch (error) {
    res.status(500).json({ message: 'Error al guardar producto' });
  }
});

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

app.get('/api/stats/:storeId', authenticateToken, async (req, res) => {
  try {
    const store = await Store.findById(req.params.storeId, 'totalRevenue platformFeeOwed name subscriptionPaidUntil whatsapp');
    if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });
    if (req.user.storeId !== req.params.storeId && req.user.name !== 'jtl') {
        return res.status(403).json({ message: 'No tienes permiso para ver estas estadísticas' });
    }
    res.status(200).json(store);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener stats' });
  }
});

app.post('/api/stores/resetprofit', authenticateToken, async (req, res) => {
    try {
        const storeId = req.user.storeId;
        const updatedStore = await Store.findByIdAndUpdate(storeId, {
            totalRevenue: 0,
            platformFeeOwed: 0
        }, { new: true });
        res.status(200).json({
            message: 'Ganancias y comisiones reseteadas',
            newStats: { totalRevenue: updatedStore.totalRevenue, platformFeeOwed: updatedStore.platformFeeOwed }
        });
    } catch (error) {
        res.status(500).json({ message: 'Error al resetear ganancias' });
    }
});

app.put('/api/stores/password', authenticateToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await Store.findByIdAndUpdate(req.user.storeId, { password: hashedPassword });
        res.status(200).json({ message: 'Contraseña actualizada con éxito' });
    } catch (error) {
        res.status(500).json({ message: 'Error al cambiar contraseña' });
    }
});

app.delete('/api/stores/my-data', authenticateToken, async (req, res) => {
    try {
        const storeId = req.user.storeId;
        if (req.user.name === 'jtl') {
            return res.status(403).json({ message: 'La tienda JTL no puede usar esta función.' });
        }
        await Product.deleteMany({ store: storeId });
        await Store.findByIdAndUpdate(storeId, {
            totalRevenue: 0,
            platformFeeOwed: 0
        });
        res.status(200).json({ message: 'Todos tus productos y datos de ganancias han sido eliminados.' });
    } catch (error) {
        res.status(500).json({ message: 'Error al borrar los datos de la tienda' });
    }
});

app.post('/api/stores/register', async (req, res) => {
  try {
    const { name, password, whatsapp } = req.body;
    const existingStore = await Store.findOne({ name: name });
    if (existingStore) {
      return res.status(400).json({ message: 'Ya existe una tienda con ese nombre' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    let amount = DEFAULT_MONTHLY_AMOUNT;
    const setting = await Setting.findOne({ key: 'monthly_amount' });
    if(setting) amount = Number(setting.value) || DEFAULT_MONTHLY_AMOUNT;

    const newStore = new Store({
      name: name,
      password: hashedPassword,
      whatsapp: whatsapp || '',
      subscriptionPaidUntil: new Date(Date.now() + SUBSCRIPTION_MS)
    });
    await newStore.save();
    res.status(201).json({ message: 'Tienda registrada con éxito', storeId: newStore._id });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/stores', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { name, password, whatsapp, isPublic } = req.body;
        if (!name || !password) {
            return res.status(400).json({ message: 'Nombre y contraseña requeridos' });
        }
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
          isPublic: isPublic || false,
          subscriptionPaidUntil: new Date(Date.now() + SUBSCRIPTION_MS)
        });
        await newStore.save();
        res.status(201).json({ message: 'Tienda creada con éxito', store: newStore });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

app.put('/api/stores/:id/public', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        const { isPublic } = req.body;
        const updatedStore = await Store.findByIdAndUpdate(storeId, { isPublic: isPublic }, { new: true });
        res.status(200).json({ message: 'Estado de tienda actualizado', store: updatedStore });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

app.put('/api/stores/:id/pay', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        const store = await Store.findById(storeId);
        if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });
        
        const now = Date.now();
        const start = store.subscriptionPaidUntil && store.subscriptionPaidUntil.getTime() > now ? store.subscriptionPaidUntil.getTime() : now;
        const newPaidUntil = new Date(start + SUBSCRIPTION_MS);
        
        store.subscriptionPaidUntil = newPaidUntil;
        store.blocked = false;
        await store.save();
        
        res.status(200).json({ message: 'Pago registrado con éxito', store: store });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

app.delete('/api/stores/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        if (storeId === req.user.storeId) {
            return res.status(400).json({ message: 'No puedes borrar tu propia tienda (JTL)' });
        }
        const deletedStore = await Store.findByIdAndDelete(storeId);
        if (!deletedStore) return res.status(404).json({ message: 'Tienda no encontrada' });
        await Product.deleteMany({ store: storeId });
        res.status(200).json({ message: 'Tienda y todos sus productos eliminados' });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

app.get('/api/settings/monthly_amount', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        let setting = await Setting.findOne({ key: 'monthly_amount' });
        if (!setting) {
            setting = await new Setting({ key: 'monthly_amount', value: DEFAULT_MONTHLY_AMOUNT }).save();
        }
        res.json(setting);
    } catch (error) {
        res.status(500).json({ message: 'Error obteniendo configuración' });
    }
});

app.put('/api/settings/monthly_amount', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { value } = req.body;
        if (!value || Number(value) <= 0) {
            return res.status(400).json({ message: 'Monto inválido' });
        }
        const updatedSetting = await Setting.findOneAndUpdate(
            { key: 'monthly_amount' },
            { value: Number(value) },
            { new: true, upsert: true }
        );
        res.json(updatedSetting);
    } catch (error) {
        res.status(500).json({ message: 'Error actualizando configuración' });
    }
});


// 8. Iniciar el servidor (Para Render)
const port_render = process.env.PORT || 3000; 
app.listen(port_render, '0.0.0.0', () => { 
    console.log(`Servidor de Express escuchando en el puerto ${port_render}`); 
});

// 9. Exportar para Vercel (No es necesario si usas Render, pero no hace daño)
module.exports = app;
