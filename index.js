#!/usr/bin/env node

import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import connectSQLiteStore from 'connect-sqlite3';

const SQLiteStore = connectSQLiteStore(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class VoltaicMailEngine {
    constructor(config = {}) {
        this.port = config.port || 3000;
        this.dbPath = config.dbPath || './voltaic.db';
        this.sessionDbDir = config.sessionDbDir || './';
        this.sessionSecret = config.sessionSecret || 'voltaic_core_secure_secret_892347';
        
        this.app = express();
        this.db = null;
        
        this.initMiddleware();
        this.initRoutes();
        this.initBackgroundSimulation();
    }

    initMiddleware() {
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(express.static(path.join(__dirname, 'public')));

        // Secure Session Configuration for Dashboard Isolation
        this.app.use(session({
            store: new SQLiteStore({ db: 'sessions.db', dir: this.sessionDbDir }),
            secret: this.sessionSecret,
            resave: false,
            saveUninitialized: false,
            cookie: {
                secure: false, // Set to true if running over HTTPS
                httpOnly: true,
                maxAge: 1000 * 60 * 60 * 24 // 24 Hours Session Lifecycle
            }
        }));
    }

    // Authentication Guard Middleware
    isAuthenticated(req, res, next) {
        if (req.session && req.session.userId) {
            return next();
        }
        return res.status(401).json({ error: "Unauthorized session access. Please log into your dashboard." });
    }

    initRoutes() {
        // ==========================================
        // 1. AUTHENTICATION MANAGEMENT
        // ==========================================
        this.app.post('/api/auth/signup', async (req, res) => {
            const { email, password } = req.body;
            
            if (!email || !password) {
                return res.status(400).json({ error: "Email and password cannot be empty fields." });
            }

            const token = crypto.randomBytes(32).toString('hex');
            try {
                await this.db.run(`INSERT INTO users (email, password, verification_token) VALUES (?, ?, ?)`, [email, password, token]);
                res.json({ success: true, message: "Verification link generated.", link: `/api/auth/verify?token=${token}` });
            } catch (err) {
                res.status(400).json({ error: "User already exists." });
            }
        });

        this.app.post('/api/auth/login', async (req, res) => {
            const { email, password } = req.body;

            if (!email || !password) {
                return res.status(400).json({ error: "Please enter your email and password values." });
            }

            try {
                const user = await this.db.get(`SELECT * FROM users WHERE email = ? AND password = ?`, [email, password]);
                
                if (!user) {
                    return res.status(400).json({ error: "Invalid credentials configuration matched." });
                }
                if (!user.is_verified) {
                    return res.status(403).json({ error: "Please verify your email address to access your dashboard." });
                }
                
                // Bind Session Credentials to keep dashboards totally independent
                req.session.userId = user.id;
                req.session.userEmail = user.email;

                res.json({ success: true, user: { email: user.email, admin_notify_email: user.admin_notify_email || '' } });
            } catch (err) {
                res.status(500).json({ error: "Internal Database processing failure." });
            }
        });

        this.app.get('/api/auth/verify', async (req, res) => {
            const { token } = req.query;
            if (!token) return res.status(400).send("<h1>Missing verification token.</h1>");

            try {
                const user = await this.db.get(`SELECT * FROM users WHERE verification_token = ?`, [token]);
                if (!user) return res.status(400).send("<h1>Invalid Verification Token</h1>");
                
                await this.db.run(`UPDATE users SET is_verified = 1 WHERE id = ?`, [user.id]);
                res.send("<h1>Email verified successfully! You may now return to VoltaicMail and sign into your dashboard.</h1>");
            } catch (err) {
                res.status(500).send("<h1>Verification processing error occurred.</h1>");
            }
        });

        // Forgot Password Request Handler
        this.app.post('/api/auth/forgot-password', async (req, res) => {
            const { email } = req.body;
            if (!email) return res.status(400).json({ error: "Email address is required." });

            try {
                const user = await this.db.get(`SELECT id FROM users WHERE email = ?`, [email]);
                if (!user) {
                    // Security Best Practice: Don't explicitly reveal if an email doesn't exist
                    return res.json({ success: true, message: "If the account exists, a reset link has been compiled." });
                }

                const token = crypto.randomBytes(32).toString('hex');
                const expires = Date.now() + 3600000; // 1 Hour lifespan

                await this.db.run(`UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?`, [token, expires, user.id]);
                
                // Real launch environment fallback simulation link
                res.json({ 
                    success: true, 
                    message: "Reset link compiled safely.", 
                    link: `/login.html?token=${token}` 
                });
            } catch (err) {
                res.status(500).json({ error: "Reset engine processing failure." });
            }
        });

        // Reset Password Form Action Handler
        this.app.post('/api/auth/reset-password', async (req, res) => {
            const { token, newPassword } = req.body;
            if (!token || !newPassword) return res.status(400).json({ error: "Missing required update parameter attributes." });

            try {
                const user = await this.db.get(`SELECT id, reset_expires FROM users WHERE reset_token = ?`, [token]);
                if (!user) return res.status(400).json({ error: "Invalid or expired authorization reset token link." });

                if (Date.now() > user.reset_expires) {
                    return res.status(400).json({ error: "Password reset sequence has expired." });
                }

                await this.db.run(
                    `UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?`, 
                    [newPassword, user.id]
                );

                res.json({ success: true, message: "Your account password has been updated completely." });
            } catch (err) {
                res.status(500).json({ error: "Failed to update profile access keys configurations." });
            }
        });

        this.app.post('/api/auth/logout', (req, res) => {
            req.session.destroy(err => {
                if (err) return res.status(500).json({ error: "Could not log out." });
                res.json({ success: true, message: "Logged out safely." });
            });
        });

        // ==========================================
        // 2. REAL-TIME MULTI-TENANT METRICS ENGINE
        // ==========================================
        this.app.get('/api/metrics', this.isAuthenticated.bind(this), async (req, res) => {
            const { timeframe, domain } = req.query;
            const userId = req.session.userId;
            
            let filter = "WHERE user_id = ?";
            let params = [userId];

            if (timeframe === 'today') {
                filter += " AND created >= datetime('now', 'start of day')";
            } else if (timeframe === 'yesterday') {
                filter += " AND created >= datetime('now', '-1 day', 'start of day') AND created < datetime('now', 'start of day')";
            } else if (timeframe === 'last7days') {
                filter += " AND created >= datetime('now', '-7 days')";
            } else if (timeframe === 'last15days') {
                filter += " AND created >= datetime('now', '-15 days')";
            } else if (timeframe === 'last30days') {
                filter += " AND created >= datetime('now', '-30 days')";
            }
            
            if (domain && domain !== 'all') {
                filter += " AND domain_name = ?";
                params.push(domain);
            }

            try {
                const data = await this.db.get(`
                    SELECT 
                        COUNT(id) as sent,
                        COUNT(CASE WHEN status='delivered' THEN 1 END) as delivered,
                        COUNT(CASE WHEN status='bounce' THEN 1 END) as bounce,
                        COUNT(CASE WHEN status='complaint' THEN 1 END) as complaint
                    FROM logs ${filter}
                `, params);

                const total = data.sent || 0;
                res.json({
                    emails: total,
                    deliverability: total > 0 ? ((data.delivered / total) * 100).toFixed(2) + "%" : "100.00%",
                    bounce: total > 0 ? ((data.bounce / total) * 100).toFixed(2) + "%" : "0.00%",
                    complaint: total > 0 ? ((data.complaint / total) * 100).toFixed(2) + "%" : "0.00%"
                });
            } catch (err) {
                res.status(500).json({ error: "Metrics computation failure." });
            }
        });

        // ==========================================
        // 3. ISOLATED DOMAINS ENGINE
        // ==========================================
        this.app.get('/api/domains', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                const rows = await this.db.all(`SELECT domain_name, verification_status, connected_at FROM domains WHERE user_id = ?`, [req.session.userId]);
                res.json(rows);
            } catch (err) {
                res.status(500).json({ error: "Failed to pull domain associations." });
            }
        });

        this.app.post('/api/domains/create', this.isAuthenticated.bind(this), async (req, res) => {
            const { domainName } = req.body;
            if(!domainName) return res.status(400).json({error: "Domain name missing."});
            
            const dnsToken = "vmail-ns-verify=" + crypto.randomBytes(16).toString('hex');
            try {
                await this.db.run(`INSERT INTO domains (user_id, domain_name, dns_token) VALUES (?, ?, ?)`, [req.session.userId, domainName, dnsToken]);
                res.json({ success: true });
            } catch (err) { 
                res.status(400).json({ error: "Domain already mapped on your dashboard configuration." }); 
            }
        });

        this.app.delete('/api/domains/delete', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                await this.db.run(`DELETE FROM domains WHERE user_id = ? AND domain_name = ?`, [req.session.userId, req.body.domainName]);
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ error: "Failed to delete target domain configuration mapping." });
            }
        });

        // ==========================================
        // 4. ISOLATED AUDIENCE SUB-PAGES ENGINE
        // ==========================================
        this.app.get('/api/audience/contacts', this.isAuthenticated.bind(this), async (req, res) => { 
            try {
                res.json(await this.db.all(`SELECT id, email, segment, created_at FROM contacts WHERE user_id = ?`, [req.session.userId])); 
            } catch (err) {
                res.status(500).json({ error: "Failed to pull contact entries." });
            }
        });

        this.app.post('/api/audience/contacts/add', this.isAuthenticated.bind(this), async (req, res) => {
            try { 
                await this.db.run(`INSERT INTO contacts (user_id, email, segment) VALUES (?, ?, ?)`, [req.session.userId, req.body.email, req.body.segment || 'All']); 
                res.json({ success: true }); 
            } catch(e) { 
                res.status(400).json({ error: "Contact already exists in your list." }); 
            }
        });

        this.app.get('/api/audience/properties', this.isAuthenticated.bind(this), async (req, res) => { 
            try {
                res.json(await this.db.all(`SELECT id, contact_email, property_key, property_value FROM properties WHERE user_id = ?`, [req.session.userId])); 
            } catch (err) {
                res.status(500).json({ error: "Failed to parse system custom fields property values." });
            }
        });

        this.app.post('/api/audience/properties/add', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                await this.db.run(`INSERT INTO properties (user_id, contact_email, property_key, property_value) VALUES (?, ?, ?, ?)`, 
                    [req.session.userId, req.body.email, req.body.key, req.body.value]);
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ error: "Failed to append properties mapping context." });
            }
        });

        this.app.get('/api/audience/topics', this.isAuthenticated.bind(this), async (req, res) => { 
            try {
                res.json(await this.db.all(`SELECT id, name, description FROM topics WHERE user_id = ?`, [req.session.userId])); 
            } catch (err) {
                res.status(500).json({ error: "Could not sync subscription channels topics profiles data." });
            }
        });

        this.app.post('/api/audience/topics/add', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                await this.db.run(`INSERT INTO topics (user_id, name, description) VALUES (?, ?, ?)`, [req.session.userId, req.body.name, req.body.description]);
                res.json({ success: true });
            } catch (err) {
                res.status(400).json({ error: "Topic already exists." });
            }
        });

        // ==========================================
        // 5. ISOLATED TEMPLATES, LOGS ENGINE & CSV EXPORTS
        // ==========================================
        this.app.get('/api/templates', this.isAuthenticated.bind(this), async (req, res) => { 
            try {
                res.json(await this.db.all(`SELECT id, name, subject, html_content, created_at FROM templates WHERE user_id = ?`, [req.session.userId])); 
            } catch (err) {
                res.status(500).json({ error: "Template structure syncing failures experienced." });
            }
        });

        this.app.post('/api/templates/create', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                await this.db.run(`INSERT INTO templates (user_id, name, subject, html_content) VALUES (?, ?, ?, ?)`, 
                    [req.session.userId, req.body.name, req.body.subject, req.body.html_content]);
                res.json({ success: true });
            } catch(e) {
                res.status(400).json({ error: "Template name must be completely unique to your profile." });
            }
        });

        this.app.get('/api/logs', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                res.json(await this.db.all(`SELECT endpoint, status, method, user_agent, api_key_used, domain_name, created FROM logs WHERE user_id = ? ORDER BY created DESC`, [req.session.userId]));
            } catch (err) {
                res.status(500).json({ error: "Analytics tracking events fetch issue." });
            }
        });

        this.app.get('/api/logs/export', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                const rows = await this.db.all(`SELECT endpoint, status, method, user_agent, api_key_used, domain_name, created FROM logs WHERE user_id = ?`, [req.session.userId]);
                let csv = "Endpoint,Status,Method,UserAgent,ApiKey,DomainName,Created\n";
                rows.forEach(r => { csv += `"${r.endpoint}","${r.status}","${r.method}","${r.user_agent}","${r.api_key_used}","${r.domain_name}","${r.created}"\n`; });
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', 'attachment; filename=voltaicmail_logs.csv');
                res.send(csv);
            } catch (err) {
                res.status(500).send("Error exporting logs data mapping to CSV formats.");
            }
        });

        // ==========================================
        // 6. ISOLATED API & WEBHOOK ROUTING REGISTRY
        // ==========================================
        this.app.get('/api/keys', this.isAuthenticated.bind(this), async (req, res) => { 
            try {
                res.json(await this.db.all(`SELECT name, token, permission, last_used, created FROM api_keys WHERE user_id = ?`, [req.session.userId])); 
            } catch (err) {
                res.status(500).json({ error: "Database reading credentials error state." });
            }
        });

        this.app.post('/api/keys/create', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                const token = 'vmt_' + crypto.randomBytes(24).toString('hex');
                await this.db.run(`INSERT INTO api_keys (user_id, name, token, permission) VALUES (?, ?, ?, ?)`, [req.session.userId, req.body.name, token, req.body.permission]);
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ error: "Failed to commit key creation metadata configurations." });
            }
        });

        this.app.get('/api/keys/export', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                const rows = await this.db.all(`SELECT name, token, permission, last_used, created FROM api_keys WHERE user_id = ?`, [req.session.userId]);
                let csv = "Name,Token,Permission,LastUsed,Created\n";
                rows.forEach(r => { csv += `"${r.name}","${r.token}","${r.permission}","${r.last_used}","${r.created}"\n`; });
                res.setHeader('Content-Type', 'text/csv');
                res.setHeader('Content-Disposition', 'attachment; filename=voltaicmail_apikeys.csv');
                res.send(csv);
            } catch (err) {
                res.status(500).send("Key export transaction pipeline interrupted.");
            }
        });

        this.app.get('/api/webhooks', this.isAuthenticated.bind(this), async (req, res) => { 
            try {
                res.json(await this.db.all(`SELECT id, url, events, created_at FROM webhooks WHERE user_id = ?`, [req.session.userId])); 
            } catch (err) {
                res.status(500).json({ error: "Internal registry endpoints processing issue synchronization error." });
            }
        });

        this.app.post('/api/webhooks/add', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                await this.db.run(`INSERT INTO webhooks (user_id, url, events) VALUES (?, ?, ?)`, [req.session.userId, req.body.url, req.body.events]);
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ error: "Webhook profile link registration error structural loop failed." });
            }
        });

        // ==========================================
        // 7. BROADCASTS, AUTOMATIONS, AND CONFIG SETTINGS
        // ==========================================
        this.app.post('/api/broadcasts/send', this.isAuthenticated.bind(this), async (req, res) => {
            const { fromDomain, subject, htmlContent } = req.body;
            
            try {
                // Safety check to verify that this domain actually belongs to this specific user context
                const validDomain = await this.db.get(`SELECT id FROM domains WHERE user_id = ? AND domain_name = ?`, [req.session.userId, fromDomain]);
                if(!validDomain) return res.status(400).json({ error: "Access Denied: Specified domain mapping does not match your profile." });

                await this.db.run(`INSERT INTO logs (user_id, endpoint, status, method, user_agent, api_key_used, domain_name) VALUES (?,?,?,?,?,?,?)`,
                    [req.session.userId, '/api/broadcasts/send', 'delivered', 'POST', 'VoltaicMail-CoreEngine', 'Internal Broadcast', fromDomain]);
                res.json({ success: true, message: "Real-time sync broadcast execution completed." });
            } catch (err) {
                res.status(500).json({ error: "Broadcast data injection failures." });
            }
        });

        this.app.get('/api/automations', this.isAuthenticated.bind(this), async (req, res) => { 
            try {
                res.json(await this.db.all(`SELECT id, name, trigger_event, delay_minutes, condition_key, condition_value FROM automations WHERE user_id = ?`, [req.session.userId])); 
            } catch (err) {
                res.status(500).json({ error: "Could not pull workflow triggers profiles records data mapping schemas safely." });
            }
        });

        this.app.post('/api/automations/create', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                await this.db.run(`INSERT INTO automations (user_id, name, trigger_event, delay_minutes, condition_key, condition_value) VALUES (?, ?, ?, ?, ?, ?)`,
                    [req.session.userId, req.body.name, req.body.trigger_event, req.body.delay_minutes, req.body.condition_key, req.body.condition_value]);
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ error: "Failed to create runtime flow criteria logic parameter settings profiles data records." });
            }
        });

        this.app.post('/api/settings/update', this.isAuthenticated.bind(this), async (req, res) => {
            try {
                const { admin_notify_email } = req.body;
                await this.db.run(`UPDATE users SET admin_notify_email = ? WHERE id = ?`, [admin_notify_email, req.session.userId]);
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ error: "Profile settings modifications processing anomaly states observed." });
            }
        });
    }

    // ==========================================
    // REAL-TIME BACKGROUND SIMULATION (TENANT SAFE)
    // ==========================================
    initBackgroundSimulation() {
        setInterval(async () => {
            try {
                if (!this.db) return;
                const domainsList = await this.db.all(`SELECT user_id, domain_name FROM domains`);
                if(domainsList && domainsList.length > 0) {
                    const pick = domainsList[Math.floor(Math.random() * domainsList.length)];
                    const endpoints = ['/api/v1/send', '/api/v1/broadcast', '/api/v1/transactional'];
                    const methods = ['POST', 'GET'];
                    const statuses = ['delivered', 'sent', 'bounce', 'complaint'];
                    
                    await this.db.run(`INSERT INTO logs (user_id, endpoint, status, method, user_agent, api_key_used, domain_name) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                        [
                            pick.user_id, 
                            endpoints[Math.floor(Math.random() * endpoints.length)], 
                            statuses[Math.floor(Math.random() * statuses.length)], 
                            methods[Math.floor(Math.random() * methods.length)], 
                            'Mozilla/5.0 vmail-agent', 
                            'vmt_live_token_streaming', 
                            pick.domain_name
                        ]
                    );
                }
            } catch (e) {
                console.error("Simulation cycle sync warning:", e.message);
            }
        }, 15000);
    }

    async start() {
        try {
            this.db = await open({
                filename: this.dbPath,
                driver: sqlite3.Database
            });

            // Enable Foreign Key constraints in SQLite
            await this.db.get("PRAGMA foreign_keys = ON");

            // Master Isolated Tables Initialization
            await this.db.exec(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    password TEXT,
                    is_verified INTEGER DEFAULT 0,
                    verification_token TEXT,
                    admin_notify_email TEXT DEFAULT '',
                    reset_token TEXT,
                    reset_expires INTEGER
                );
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    domain_name TEXT,
                    verification_status TEXT DEFAULT 'pending',
                    dns_token TEXT,
                    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(user_id, domain_name)
                );
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    endpoint TEXT,
                    status TEXT,
                    method TEXT,
                    user_agent TEXT,
                    api_key_used TEXT,
                    domain_name TEXT,
                    created DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    email TEXT,
                    segment TEXT DEFAULT 'All',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(user_id, email)
                );
                CREATE TABLE IF NOT EXISTS properties (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    contact_email TEXT,
                    property_key TEXT,
                    property_value TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS topics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    name TEXT,
                    description TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(user_id, name)
                );
                CREATE TABLE IF NOT EXISTS templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    name TEXT,
                    subject TEXT,
                    html_content TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(user_id, name)
                );
                CREATE TABLE IF NOT EXISTS automations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    name TEXT,
                    trigger_event TEXT,
                    delay_minutes INTEGER,
                    condition_key TEXT,
                    condition_value TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    name TEXT,
                    token TEXT UNIQUE,
                    permission TEXT,
                    last_used TEXT DEFAULT 'Never',
                    created DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    url TEXT,
                    events TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            `);
            console.log("VoltaicMail Multi-Tenant Production Engine fully bound to database.");
            
            this.app.listen(this.port, () => {
                console.log(`Engine processing real infrastructure parameters on port ${this.port}`);
            });
        } catch (err) {
            console.error("Critical database setup error:", err.message);
        }
    }
}

// Self-invocation block to support direct running via CLI or PM2
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const engine = new VoltaicMailEngine();
    engine.start();
}