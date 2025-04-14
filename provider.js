const express = require('express');
const app = express();
const db = require('./util/database');
const session = require('express-session');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');
const ejs=require('ejs');
const path=require('path');
// Environment variables
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "sso_secret_key";
const SESSION_SECRET = process.env.SESSION_SECRET || "session_secret_key";


const tokenStore = new Map();


app.use(cors({
  origin: ['http://localhost:8080'], 
  credentials: true
}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session configuration
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Home page
app.get('/', (req, res) => {
  res.render('auth-home', { 
    user: req.session.userId ? true : false 
  });
});

// Login page
app.get('/login', (req, res) => {
  // Check if request has next parameter for SSO redirect
  const next = req.query.next;
  const guid = req.query.guid;
  
  res.render('login', { 
    next: next || null,
    guid: guid || null,
    error: null
  });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const next = req.body.next;
    const guid = req.body.guid;
  
    if (!email || !password) {
      return res.render('login', { 
        next, 
        guid, 
        error: 'Email and password are required' 
      });
    }
  
    try {
      // Get user - using your original table name 'project' and column 'pass'
      const [rows] = await db.execute('SELECT * FROM project WHERE email = ?', [email]);
      
      if (rows.length === 0) {
        return res.render('login', { 
          next, 
          guid, 
          error: 'Invalid credentials' 
        });
      }
  
      const user = rows[0];
      
      // Direct password comparison since your existing DB likely doesn't have bcrypt hashes
      if (user.pass !== password) {
        return res.render('login', { 
          next, 
          guid, 
          error: 'Invalid credentials' 
        });
      }
  
      // Set session
      req.session.userId = user.id || 1; // Fallback to 1 if id doesn't exist
      req.session.email = user.email;
  
      // Check if there's a next parameter for SSO flow
      if (next) {
        return res.redirect(`/sso?next=${encodeURIComponent(next)}&guid=${guid || ''}`);
      }
  
      res.redirect('/');
    } catch (error) {
      console.error('Login error:', error);
      res.render('login', { 
        next, 
        guid, 
        error: 'Internal server error' 
      });
    }
  });
// SSO Initiation Endpoint
app.get('/sso', (req, res) => {
  const next = req.query.next;
  
  if (!req.session.userId) {
    return res.redirect(`/login?next=${encodeURIComponent(next)}`);
  }
  
  if (!next) {
    return res.status(400).send('Missing redirect URL');
  }

  try {
    // Generate GUID
    const guid = crypto.randomBytes(16).toString('hex');
    
    // Create token
    const token = jwt.sign({
      userId: req.session.userId,
      email: req.session.email
    }, SECRET_KEY, { expiresIn: '10m' });
    
    // Store token
    tokenStore.set(guid, {
      token,
      expires: Date.now() + (10 * 60 * 1000) // 10 minutes
    });
    
    // Cleanup expired token
    setTimeout(() => {
      if (tokenStore.has(guid)) {
        tokenStore.delete(guid);
      }
    }, 10 * 60 * 1000);
    
    // Redirect to client app
    res.redirect(`${next}?guid=${guid}`);
  } catch (error) {
    console.error('SSO error:', error);
    res.status(500).send('Error initiating SSO flow');
  }
});

// Token Verification Endpoint
app.get('/verify', (req, res) => {
  const guid = req.query.guid;
  
  if (!guid) {
    return res.status(400).json({ error: 'Missing GUID parameter' });
  }
  
  const tokenData = tokenStore.get(guid);
  
  if (!tokenData) {
    return res.status(401).json({ error: 'Token not found or expired' });
  }
  
  if (Date.now() > tokenData.expires) {
    tokenStore.delete(guid);
    return res.status(401).json({ error: 'Token expired' });
  }
  
  // Delete token after use
  tokenStore.delete(guid);
  
  // Return token
  res.json({ token: tokenData.token });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).send('Error during logout');
    }
    res.redirect('/');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`SSO Provider server running on port ${PORT}`);
});