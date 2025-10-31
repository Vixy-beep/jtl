// 1. Importar las librerías
const express = require('express');
const cors = require('cors');

// 2. Inicializar la aplicación
const app = express();
const port = 3000; // El puerto donde correrá el servidor

// 3. Configurar CORS (Permite que tu index.html hable con este servidor)
app.use(cors());

// 4. BASE DE DATOS FALSA (Totalmente separada de Jorise)
const DUMMY_DB = {
  'jtl': [
    { id: 'p1', name: 'Pan (desde el Servidor)', category: 'Panadería', price: 90.00, stock: 10, img: 'https://via.placeholder.com/400x300?text=Pan+Server' },
    { id: 'p2', name: 'Café (desde el Servidor)', category: 'Bebidas', price: 260.00, stock: 8, img: 'https://via.placeholder.com/400x300?text=Cafe+Server' }
  ],
  'otra_tienda': [
     { id: 'p3', name: 'Producto de otra tienda', category: 'General', price: 100.00, stock: 5, img: 'https://via.placeholder.com/400x300?text=Otro' }
  ]
};

// 5. Crear la ruta API (Endpoint)
app.get('/api/products/:storeId', (req, res) => {
  const storeId = req.params.storeId;
  console.log(`Petición recibida para la tienda: ${storeId}`);

  const products = DUMMY_DB[storeId];

  if (products) {
    res.json(products);
  } else {
    res.json([]);
  }
});

// 6. Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor de Tienda JTL escuchando en http://localhost:${port}`);
});
