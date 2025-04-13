// ===== IMPORTS =====
// Core dependencies
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

// Configuration imports
const { admin, db } = require('./config/firebase');
const routes = require('./routes/route');
const passwordResetRoutes = require('./routes/password-reset');

// Logging
const winston = require('winston');

// ===== CONFIGURATION =====
dotenv.config();

// Constants
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'miralhu';
const SERVER_ID = 2;

// ===== MIDDLEWARE SETUP =====
// Logger configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'user-service' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'all.log', level: 'info' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console()
    ]
});

// ===== EXPRESS APP SETUP =====
const app = express();

// Apply global middleware
app.use(cors());
app.use(bodyParser.json());

// ===== CUSTOM MIDDLEWARE =====
// Request logging middleware
const requestLogger = (req, res, next) => {
    console.log(`[${req.method}] ${req.url} - Body:`, req.body);
    const startTime = Date.now();

    const originalSend = res.send;
    let statusCode;

    res.send = function (body) {
        statusCode = res.statusCode;
        originalSend.call(this, body);
    };

    res.on('finish', async () => {
        const logLevel = res.statusCode >= 400 ? 'error' : 'info';
        const responseTime = Date.now() - startTime;
        const logData = {
            logLevel,
            timestamp: admin.firestore.Timestamp.fromDate(new Date()), // Changed this line
            method: req.method,
            url: req.url,
            path: req.path,
            query: req.query || {},
            params: req.params || {},
            status: Number(statusCode || res.statusCode), // Ensure it's a number
            responseTime: Number(responseTime),
            body: req.body,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('user-agent'),
            protocol: req.protocol,
            hostname: req.hostname,
            serverId: Number(SERVER_ID), // Ensure it's a number
            system: {
                nodeVersion: process.version,
                environment: process.env.NODE_ENV || 'development',
                pid: Number(process.pid),
                memoryUsage: {
                    // Ensure all memory values are numbers
                    heapTotal: Number(process.memoryUsage().heapTotal),
                    heapUsed: Number(process.memoryUsage().heapUsed),
                    external: Number(process.memoryUsage().external),
                    rss: Number(process.memoryUsage().rss),
                    arrayBuffers: Number(process.memoryUsage().arrayBuffers || 0)
                }
            }
        };
        
        logger.log(logLevel, 'Request completed', logData);

        try {
            await db.collection('logs').add(logData);   
        } catch (error) {
            logger.error('Failed to log request', error);
        }
    });

    next();
};

// JWT verification middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['x-access-token'];
    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Failed to authenticate token' });
        }
        req.username = decoded.username;
        next();
    });
};

// Apply custom middleware
app.use(requestLogger);

// ===== ROUTES =====
// API routes
app.use('/api', routes);
app.use('/api/', passwordResetRoutes);

// Direct routes
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // SIMULACION DE AUTENTICACION DEBERIA VALIDARSE CON UNA BASE DE DATOS
    if (username === 'admin' && password === 'admin') {
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '2m' });
        res.status(200).json({ message: 'Login successful', token });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

// ===== ERROR HANDLING =====
// 404 handler
app.use((req, res, next) => {
    res.status(404).json({ message: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error', { error: err.message, stack: err.stack });
    res.status(500).json({ message: 'Internal server error' });
});

// ===== SERVER INITIALIZATION =====
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} (No Rate Limit Version)`);
});

// For testing/module exports
module.exports = app;

// Configuración CORS actualizada
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://logs-dashboard.onrender.com', 'http://localhost:3000'] 
    : 'http://localhost:3000',
  credentials: true
}));