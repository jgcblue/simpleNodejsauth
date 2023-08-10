const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key'; // Change this to a strong secret key

app.use(bodyParser.json());
app.use(cors());
// Initialize SQLite database
const db = new sqlite3.Database('users.db');

// Create users table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
  )
`);

// Routes
/*
app.post('/signup', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [req.body.username, hashedPassword], (err) => {
      if (err) {
        res.status(500).json({ message: 'Error creating user' }); // Send error response as JSON
      } else {
        res.status(201).json({ message: 'User created successfully' }); // Send success response as JSON
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user' }); // Send error response as JSON
  }
});
*/

app.post('/signup', async (req, res) => {
  try {
    // Check if user already exists
    db.get('SELECT * FROM users WHERE username = ?', [req.body.username], async (err, existingUser) => {
      if (err) {
        res.status(500).json({ message: 'Error creating user' });
      } else if (existingUser) {
        res.status(409).json({ message: 'User already exists' }); // User conflict
      } else {
        // User does not exist, proceed with signup
        try {
          const hashedPassword = await bcrypt.hash(req.body.password, 10);
          db.run('INSERT INTO users (username, password) VALUES (?, ?)', [req.body.username, hashedPassword], (insertErr) => {
            if (insertErr) {
              res.status(500).json({ message: 'Error creating user' });
            } else {
              res.status(201).json({ message: 'User created successfully' });
            }
          });
        } catch (error) {
          res.status(500).json({ message: 'Error creating user' });
        }
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user' });
  }
});





app.post('/login', async (req, res) => {
console.log(req);
  db.get('SELECT * FROM users WHERE username = ?', [req.body.username], async (err, user) => {
    if (err) {
      res.status(500).send('Authentication error');
    } else if (user) {
      try {
        if (await bcrypt.compare(req.body.password, user.password)) {
          const token = jwt.sign({ username: user.username }, SECRET_KEY);
          res.json({ token });
        } else {
          res.status(401).send('Authentication failed');
        }
      } catch (error) {
        res.status(500).send('Authentication error');
      }
    } else {
      res.status(401).send('User not found');
    }
  });
});

// Protected route
app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).send('No token provided');
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).send('Token invalid');
    }
    res.json({ message: 'Protected resource accessed', user: decoded });
  });
});
app.get('/check-token', (req, res) => {
  const receivedToken = req.headers.authorization?.split(' ')[1];

  if (!receivedToken) {
    return res.status(401).json({ message: 'Token missing' });
  }

  jwt.verify(receivedToken, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token invalid' });
    }
    res.json({ message: 'Token valid', user: decoded });
  });
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

