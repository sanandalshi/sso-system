const express = require('express');
const app = express();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const ejs=require('ejs');
const path=require('path');
// Environment variables
const PORT = process.env.PORT || 8080;
const AUTH_SERVER = process.env.AUTH_SERVER || 'http://localhost:3000';
const SECRET_KEY = process.env.JWT_SECRET || "sso_secret_key";
const SESSION_SECRET = process.env.SESSION_SECRET || "client_session_secret";

// Middleware setup
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
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Home route - handles SSO callback with GUID
app.get('/', async (req, res) => {
  // If this is an SSO callback with GUID
  if (req.query.guid) {
    try {
      // Verify the GUID with the auth server
      const response = await axios.get(`${AUTH_SERVER}/verify?guid=${req.query.guid}`);
      const { token } = response.data;
      
      // Verify the JWT token
      const decoded = jwt.verify(token, SECRET_KEY);
      
      // Set user session
      req.session.userId = decoded.userId;
      req.session.email = decoded.email;
      
      return res.redirect('/dashboard');
    } catch (error) {
      console.error('SSO verification error:', error.message);
      return res.status(401).render('error', { 
        message: 'Authentication failed. Please try again.' 
      });
    }
  }
  
  // Regular home page
  res.render('home', { 
    user: req.session.userId ? true : false 
  });
});

// Protected dashboard page
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  res.render('dashboard', { 
    email: req.session.email 
  });
});

// Login redirect to SSO provider
app.get('/login', (req, res) => {
  res.redirect(`${AUTH_SERVER}/sso?next=${encodeURIComponent(`http://localhost:${PORT}`)}`);
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
  console.log(`Client Application server running on port ${PORT}`);
});



// const express = require('express');
// const app = express();
// const session = require('express-session');
// const cookieParser = require('cookie-parser');
// const bodyParser = require('body-parser');
// const axios = require('axios');
// const jwt = require('jsonwebtoken');
// const path = require('path');

// // Environment variables
// const PORT = process.env.PORT || 8080;
// const AUTH_SERVER = process.env.AUTH_SERVER || 'http://localhost:3000';
// const SECRET_KEY = process.env.JWT_SECRET || "sso_secret_key";
// const SESSION_SECRET = process.env.SESSION_SECRET || "client_session_secret";

// // Middleware setup
// app.use(cookieParser());
// app.use(bodyParser.urlencoded({ extended: false }));
// app.use(bodyParser.json());

// // Set up EJS as the view engine
// app.set('view engine', 'ejs');
// app.set('views', path.join(__dirname, 'views'));

// // Session configuration
// app.use(session({
//   secret: SESSION_SECRET,
//   resave: false,
//   saveUninitialized: false,
//   cookie: { 
//     maxAge: 24 * 60 * 60 * 1000,
//     httpOnly: true,
//     secure: process.env.NODE_ENV === 'production'
//   }
// }));

// // Home route - handles SSO callback with GUID
// app.get('/', async (req, res) => {
//   // If this is an SSO callback with GUID
//   if (req.query.guid) {
//     try {
//       // Verify the GUID with the auth server
//       const response = await axios.get(`${AUTH_SERVER}/verify?guid=${req.query.guid}`);
//       const { token } = response.data;
      
//       // Verify the JWT token
//       const decoded = jwt.verify(token, SECRET_KEY);
      
//       // Set user session
//       req.session.userId = decoded.userId;
//       req.session.email = decoded.email;
      
//       return res.redirect('/dashboard');
//     } catch (error) {
//       console.error('SSO verification error:', error.message);
//       return res.status(401).render('error', { 
//         message: 'Authentication failed. Please try again.' 
//       });
//     }
//   }
  
//   // Regular home page
//   res.render('home', { 
//     user: req.session.userId ? true : false 
//   });
// });

// // Protected dashboard page
// app.get('/dashboard', (req, res) => {
//   if (!req.session.userId) {
//     return res.redirect('/login');
//   }
  
//   res.render('dashboard', { 
//     email: req.session.email 
//   });
// });

// // Login redirect to SSO provider
// app.get('/login', (req, res) => {
//   res.redirect(`${AUTH_SERVER}/sso?next=${encodeURIComponent(`http://localhost:${PORT}`)}`);
// });

// // Logout
// app.get('/logout', (req, res) => {
//   req.session.destroy(err => {
//     if (err) {
//       console.error('Logout error:', err);
//       return res.status(500).send('Error during logout');
//     }
//     res.redirect('/');
//   });
// });

// // Start server
// app.listen(PORT, () => {
//   console.log(`Client Application server running on port ${PORT}`);
//   console.log(`Make sure you have installed EJS: npm install ejs`);
//   console.log(`Also ensure you have created the required view templates in the 'views' directory`);
// });