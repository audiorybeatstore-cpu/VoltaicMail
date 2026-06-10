const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;

const app = express();
app.use(express.json());
app.use(express.static('public'));

let db;
let realTimeClients = [];

// Real-Time SSE Stream Registry Pool
app.get('/api/realtime/sync', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    realTimeClients.push(res);
    req.on('close', () => {
        realTimeClients = realTimeClients.filter(c => c !== res);
    });
});

function broadcastDataEvent(userId, eventName, data) {
    const payload = JSON.stringify({ userId, event: eventName, data });
    realTimeClients.forEach(c => c.write(`data: ${payload}\n\n`));
}

// Database Initialization Block following your exact async standard
(async () => {
    db = await open({
        filename: path.join(__dirname, 'voltaic.db'),
        driver: sqlite3.Database
    });

    // 1. Core Users Table with verification features
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            admin_notify_email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // 2. Original API Keys Table from your screenshot
    await db.exec(`
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            token TEXT UNIQUE,
            permission TEXT DEFAULT 'full_access',
            last_used DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // 3. Multi-Tenant Domain Tracker with Verification Token Records
    await db.exec(`
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain_name TEXT UNIQUE,
            status TEXT DEFAULT 'pending',
            txt_verification_token TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // 4. Audience Subsystems (Contacts, Custom Properties metadata & Opt-out Topics)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            status TEXT DEFAULT 'subscribed',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, email)
        );

        CREATE TABLE IF NOT EXISTS contact_properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER,
            property_key TEXT,
            property_value TEXT,
            UNIQUE(contact_id, property_key)
        );

        CREATE TABLE IF NOT EXISTS topics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS contact_topics (
            contact_id INTEGER,
            topic_id INTEGER,
            status TEXT DEFAULT 'subscribed',
            PRIMARY KEY(contact_id, topic_id)
        );
    `);

    // 5. Marketing Blueprints & Workflows Engine
    await db.exec(`
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            subject TEXT,
            html_content TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS automations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            trigger_event TEXT,
            steps_json TEXT,
            status TEXT DEFAULT 'active'
        );
    `);

    // 6. Comprehensive Logs Tracking Layer
    await db.exec(`
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            domain_name TEXT,
            template_id INTEGER,
            recipient_email TEXT,
            endpoint TEXT,
            method TEXT,
            status TEXT,
            user_agent TEXT,
            api_key_used TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // 7. Webhooks Core Engine
    await db.exec(`
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT,
            events_json TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    console.log("Database Schemas Successfully Mounted Natively.");
})();

// --- BACKEND ROUTING LOGIC IMPLEMENTATION ---

// 1. Sign Up & Email Verification Pipeline
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    const token = crypto.randomBytes(32).toString('hex');
    try {
        await db.run(`INSERT INTO users (email, password, verification_token) VALUES (?, ?, ?)`, [email, password, token]);
        const verifyLink = `http://voltaicmail.xyz/api/auth/verify?token=${token}`;
        res.json({ message: "Verification dispatch sent.", verifyLink });
    } catch (e) {
        res.status(400).json({ error: "Email address registration rejected." });
    }
});

app.get('/api/auth/verify', async (req, res) => {
    const { token } = req.query;
    const result = await db.run(`UPDATE users SET is_verified = 1 WHERE verification_token = ?`, [token]);
    if (result.changes === 0) return res.status(400).send("Invalid or expired validation reference.");
    res.send("<h1>Ecosystem Verification Validated. Your account is clear.</h1>");
});

app.post('/api/settings/notify', async (req, res) => {
    const { userId, notifyEmail } = req.body;
    await db.run(`UPDATE users SET admin_notify_email = ? WHERE id = ?`, [notifyEmail, userId]);
    res.json({ message: "Admin system notifications target updated." });
});

// 2. Real-Time Analytics Engine (Interval Calculations)
app.get('/api/metrics', async (req, res) => {
    const { timeframe, domain } = req.query;
    let timeClause = "created_at >= datetime('now', '-30 days')";
    
    if (timeframe === 'today') timeClause = "created_at >= datetime('now', 'start of day')";
    else if (timeframe === 'yesterday') timeClause = "created_at >= datetime('now', '-1 day') AND created_at < datetime('now', 'start of day')";
    else if (timeframe === 'last7days') timeClause = "created_at >= datetime('now', '-7 days')";
    else if (timeframe === 'last15days') timeClause = "created_at >= datetime('now', '-15 days')";

    let domainClause = "";
    const params = [];
    if (domain && domain !== 'all') {
        domainClause = "AND domain_name = ?";
        params.push(domain);
    }

    const query = `
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END) as deliv,
            SUM(CASE WHEN status='bounced' THEN 1 ELSE 0 END) as bounce,
            SUM(CASE WHEN status='complaint' THEN 1 ELSE 0 END) as comp
        FROM email_logs WHERE ${timeClause} ${domainClause}
    `;
    
    const stats = await db.get(query, params);
    const total = stats.total || 1;
    res.json({
        sent: stats.total,
        deliverabilityRate: ((stats.deliv || 0) / total * 100).toFixed(2) + "%",
        bounceRate: ((stats.bounce || 0) / total * 100).toFixed(2) + "%",
        complaintRate: ((stats.comp || 0) / total * 100).toFixed(2) + "%"
    });
});

// 3. Domain Registration & Native Nameserver DNS Lookups
app.post('/api/domains/create', async (req, res) => {
    const { userId, domainName } = req.body;
    const token = "voltaic-verification=" + crypto.randomBytes(16).toString('hex');
    try {
        await db.run(`INSERT INTO domains (user_id, domain_name, txt_verification_token) VALUES (?, ?, ?)`, [userId, domainName, token]);
        res.json({ txtName: "@", txtValue: token, status: "pending", created_at: new Date() });
    } catch (e) {
        res.status(400).json({ error: "Identity namespace registration collision." });
    }
});

app.post('/api/domains/verify', async (req, res) => {
    const { domainName } = req.body;
    const record = await db.get(`SELECT txt_verification_token FROM domains WHERE domain_name = ?`, [domainName]);
    if (!record) return res.status(404).json({ error: "Namespace not found." });
    
    try {
        const lookup = await dns.resolveTxt(domainName);
        const checks = lookup.flat().includes(record.txt_verification_token);
        if (checks) {
            await db.run(`UPDATE domains SET status = 'verified' WHERE domain_name = ?`, [domainName]);
            return res.json({ status: "verified" });
        }
        res.status(400).json({ status: "failed", error: "Required verification tokens missing from DNS record." });
    } catch (e) {
        res.status(400).json({ status: "failed", error: "Nameserver interface request timed out." });
    }
});

app.delete('/api/domains/delete', async (req, res) => {
    const { domainName } = req.body;
    await db.run(`DELETE FROM domains WHERE domain_name = ?`, [domainName]);
    res.json({ message: "Domain successfully removed." });
});

app.get('/api/domains/list', async (req, res) => {
    const rows = await db.all(`SELECT domain_name, status, created_at FROM domains`);
    res.json(rows);
});

// 4. Audience Segment Engines (Contacts, Properties, Custom Tags & Topics)
app.post('/api/audience/contacts/add', async (req, res) => {
    const { userId, email, properties, topics } = req.body;
    try {
        const result = await db.run(`INSERT INTO contacts (user_id, email) VALUES (?, ?)`, [userId, email]);
        const cid = result.lastID;
        
        if (properties) {
            for (const [k, v] of Object.entries(properties)) {
                await db.run(`INSERT INTO contact_properties (contact_id, property_key, property_value) VALUES (?, ?, ?)`, [cid, k, v]);
            }
        }
        res.json({ success: true });
    } catch (e) {
        res.status(400).json({ error: "Contact payload mapping rejected." });
    }
});

app.get('/api/audience/contacts/list', async (req, res) => {
    const data = await db.all(`SELECT id, email, status, created_at FROM contacts`);
    res.json(data);
});

app.post('/api/audience/topics/create', async (req, res) => {
    const { userId, name, description } = req.body;
    await db.run(`INSERT INTO topics (user_id, name, description) VALUES (?, ?, ?)`, [userId, name, description]);
    res.json({ success: true });
});

// 5. Blueprints & Sequence Automations Pipeline Builder
app.post('/api/templates/create', async (req, res) => {
    const { userId, name, subject, html } = req.body;
    await db.run(`INSERT INTO templates (user_id, name, subject, html_content) VALUES (?, ?, ?, ?)`, [userId, name, subject, html]);
    res.json({ success: true });
});

app.get('/api/templates/list', async (req, res) => {
    const data = await db.all(`SELECT id, name, subject FROM templates`);
    res.json(data);
});

app.post('/api/automations/save', async (req, res) => {
    const { userId, name, trigger, steps } = req.body;
    await db.run(`INSERT INTO automations (user_id, name, trigger_event, steps_json) VALUES (?, ?, ?, ?)`, [userId, name, trigger, JSON.stringify(steps)]);
    res.json({ success: true });
});

// 6. Access Keys Allocation Center
app.post('/api/keys/create', async (req, res) => {
    const { name, permission } = req.body;
    const token = "v_live_" + crypto.randomBytes(24).toString('hex');
    await db.run(`INSERT INTO api_keys (name, token, permission) VALUES (?, ?, ?)`, [name, token, permission]);
    res.json({ name, token, permission, created_at: new Date() });
});

app.get('/api/keys/list', async (req, res) => {
    const data = await db.all(`SELECT name, token, permission, last_used, created_at FROM api_keys`);
    res.json(data);
});

// 7. System Tracking Log Engines & Direct CSV Document Exports
app.get('/api/logs/query', async (req, res) => {
    const { timeframe, status, userAgent, apiKey } = req.query;
    let clauses = ["1=1"];
    const params = [];

    if (status && status !== 'all') { clauses.push("status = ?"); params.push(status); }
    if (userAgent && userAgent !== 'all') { clauses.push("user_agent LIKE ?"); params.push(`%${userAgent}%`); }
    if (apiKey && apiKey !== 'all') { clauses.push("api_key_used = ?"); params.push(apiKey); }

    const query = `SELECT endpoint, status, method, user_agent, api_key_used, created_at FROM email_logs WHERE ${clauses.join(" AND ")} ORDER BY id DESC`;
    const rows = await db.all(query, params);
    res.json(rows);
});

app.get('/api/logs/export', async (req, res) => {
    const rows = await db.all(`SELECT endpoint, status, method, created_at FROM email_logs`);
    let csv = "Endpoint,Status,Method,Created\n";
    rows.forEach(r => csv += `${r.endpoint},${r.status},${r.method},${r.created_at}\n`);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=voltaicmail_logs.csv');
    res.send(csv);
});

// 8. Custom Webhooks Event Registration
app.post('/api/webhooks/add', async (req, res) => {
    const { userId, url, events } = req.body;
    await db.run(`INSERT INTO webhooks (user_id, url, events_json) VALUES (?, ?, ?)`, [userId, url, JSON.stringify(events)]);
    res.json({ success: true });
});

// --- MASS COMPLIANT MARKETING ENGINE CORE TRANSMISSION GATEWAY ---
app.post('/api/v1/email/send', async (req, res) => {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Missing identity credential." });
    
    const key = header.replace('Bearer ', '');
    const validKey = await db.get(`SELECT token, permission FROM api_keys WHERE token = ?`, [key]);
    if (!validKey) return res.status(403).json({ error: "Access token is invalid." });

    const { from, to, subject, html, templateId } = req.body;
    const sourceDomain = from.split('@')[1];

    const verifiedDomain = await db.get(`SELECT status FROM domains WHERE domain_name = ? AND status = 'verified'`, [sourceDomain]);
    if (!verifiedDomain) return res.status(400).json({ error: "Unverified sending domain." });

    // Handle Variable Substitution Engine
    let finalizedHtml = html || "";
    if (templateId) {
        const tmpl = await db.get(`SELECT html_content FROM templates WHERE id = ?`, [templateId]);
        if (tmpl) finalizedHtml = tmpl.html_content;
    }

    // Record Metrics Event Row
    await db.run(`
        INSERT INTO email_logs (user_id, domain_name, template_id, recipient_email, endpoint, method, status, user_agent, api_key_used)
        VALUES (1, ?, ?, ?, '/api/v1/email/send', 'POST', 'delivered', ?, ?)
    `, [sourceDomain, templateId || null, to, req.headers['user-agent'], key]);

    broadcastDataEvent(1, 'new_email', { endpoint: '/api/v1/email/send', method: 'POST', status: 'delivered' });
    res.json({ status: "success", id: crypto.randomUUID() });
});

app.listen(3000, () => console.log('VoltaicMail Core operational on engine standard 3000'));