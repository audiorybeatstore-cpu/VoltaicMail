const express = require('express');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public'));

let db;

// Initialize Database Tables
(async () => {
    db = await open({
        filename: './voltaic.db',
        driver: sqlite3.Database
    });

    // 1. API Keys Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            key TEXT UNIQUE,
            permission TEXT DEFAULT 'Full access',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used DEFAULT 'Never'
        )
    `);

    // 2. Sent Emails Log Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT,
            subject TEXT,
            status TEXT,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // 3. HTTP Request Logs Table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT,
            method TEXT,
            status INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    console.log("📁 Live VoltaicMail Database Engines Activated.");
})();

// 🚀 Production Mailer Transporter Configuration (Connected to Brevo SMTP)
const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587,
    secure: false,
    auth: {
        user: '7be885001@smtp-brevo.com', 
        // We removed the raw string here so GitHub will accept your code files
        pass: process.env.BREVO_SMTP_PASS 
    }
});

// 🔑 API 1: Fetch All Active API Keys
app.get('/api/keys', async (req, res) => {
    try {
        const keys = await db.all('SELECT * FROM api_keys ORDER BY created_at DESC');
        res.json({ success: true, keys });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 🔑 API 2: Create a New Live API Key (FIXED MULTIPLE GENERATION BUG)
app.post('/api/keys', async (req, res) => {
    const { name, permission } = req.body;
    if (!name) return res.status(400).json({ success: false, error: "Name is required" });

    try {
        const newKey = 'vm_live_' + crypto.randomBytes(16).toString('hex');
        
        // FIX: Added 'key' to column layout and securely bound the dynamic variable newKey
        await db.run(
            'INSERT INTO api_keys (name, key, permission) VALUES (?, ?, ?)',
            [name, newKey, permission || 'Full access']
        );
        
        res.json({ success: true, key: newKey });
    } catch (err) {
        console.error("Database Write Error:", err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 🔑 API 3: Delete/Revoke an API Key
app.delete('/api/keys/:id', async (req, res) => {
    try {
        await db.run('DELETE FROM api_keys WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ✉️ API 4: Send Email (Authenticated via your real API keys)
app.post('/api/send', async (req, res) => {
    const authHeader = req.headers['authorization'];
    const apiKey = authHeader ? authHeader.replace('Bearer ', '').trim() : null;

    let validKey = null;
    if (apiKey) {
        validKey = await db.get('SELECT * FROM api_keys WHERE key = ?', [apiKey]);
    }

    if (!validKey) {
        await db.run('INSERT INTO logs (endpoint, method, status) VALUES (?, ?, ?)', ['/api/send', 'POST', 401]);
        return res.status(401).json({ success: false, error: "Unauthorized: Invalid or missing API key." });
    }

    const { to, subject, text, userName } = req.body;
    if (!to || !subject || !text) {
        return res.status(400).json({ success: false, error: "Missing fields (to, subject, or text)." });
    }

    const htmlTemplate = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden;">
            <div style="background-color: #0f172a; padding: 32px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 26px;">⚡ VoltaicMail</h1>
            </div>
            <div style="padding: 40px 32px; background-color: #ffffff; color: #334155; line-height: 1.6;">
                <p style="font-size: 16px; font-weight: bold; margin-top: 0;">Hello ${userName || 'Developer'},</p>
                <p style="font-size: 15px;">${text}</p>
                <hr style="border: none; border-top: 1px solid #f1f5f9; margin: 32px 0;" />
                <p style="font-size: 12px; color: #94a3b8; text-align: center;">© 2026 VoltaicMail Inc.</p>
            </div>
        </div>
    `;

    try {
        let info = await transporter.sendMail({
            from: '"VoltaicMail API" <no-reply@voltaicmail.xyz>', // Pointing directly to your real verified domain name
            to,
            subject,
            text,
            html: htmlTemplate
        });

        await db.run('INSERT INTO emails (recipient, subject, status) VALUES (?, ?, ?)', [to, subject, 'Delivered']);
        await db.run('INSERT INTO logs (endpoint, method, status) VALUES (?, ?, ?)', ['/api/send', 'POST', 200]);
        
        const nowString = new Date().toLocaleTimeString();
        await db.run('UPDATE api_keys SET last_used = ? WHERE key = ?', [nowString, apiKey]);

        res.json({ success: true, messageId: info.messageId });
    } catch (error) {
        console.error("Mail Dispatch Failure:", error.message);
        await db.run('INSERT INTO emails (recipient, subject, status) VALUES (?, ?, ?)', [to, subject, 'Failed']);
        await db.run('INSERT INTO logs (endpoint, method, status) VALUES (?, ?, ?)', ['/api/send', 'POST', 500]);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 📊 API 5: Get Dashboard Metrics
app.get('/api/dashboard-data', async (req, res) => {
    try {
        const emails = await db.all('SELECT * FROM emails ORDER BY sent_at DESC');
        const logs = await db.all('SELECT * FROM logs ORDER BY created_at DESC');
        const totalKeys = await db.get('SELECT COUNT(*) as count FROM api_keys');
        
        res.json({
            success: true,
            emails,
            logs,
            metrics: {
                totalEmails: emails.length,
                deliverability: emails.length > 0 ? Math.round((emails.filter(e => e.status === 'Delivered').length / emails.length) * 100) : 100,
                totalKeys: totalKeys.count
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`⚡ VoltaicMail Engine live at http://localhost:${PORT}`);
});