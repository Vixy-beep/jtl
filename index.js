// index.js (El nuevo archivo de inicio para Render)
const app = require('./server.js');

// Usamos el puerto que Render nos asigne, o 3000 localmente.
const port = process.env.PORT || 3000; 

// Iniciamos el servidor
app.listen(port, () => {
    console.log(`Servidor de Express escuchando en el puerto ${port}`);
});
