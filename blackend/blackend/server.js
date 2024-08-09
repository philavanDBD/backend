const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(cors());
// app.use(bodyParser.urlencoded({ extended: true }));

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'nodejs_one'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Mysql connected...');
});

// Register
app.post('/register', (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
        return res.status(400).json({ msg: 'Please enter all fields' });
    }
    
    // Check for existing user
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Hash password
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) throw err;

            // Insert user into database
            const insertQuery = 'INSERT INTO users (email, username, password) VALUES (?, ?, ?)';
            db.query(insertQuery, [email, username, hash], (err, result) => {
                if (err) throw err;
                res.status(201).json({ msg: 'User registered successfully' });
            });
        });
    });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ msg: 'Please enter all fields' });
    }

    // Check for user
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, result) => {
        if (err) throw err;
        if (result.length === 0) {
            return res.status(400).json({ msg: 'User does not exist' });
        }

        const user = result[0];

        // Compare password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;
            if (!isMatch) {
                return res.status(400).json({ msg: 'Invalid credentials' });
            }

            // Generate JWT
            jwt.sign(
                { id: user.id },
                'your_jwt_secret',
                { expiresIn: 3600 },
                (err, token) => {
                    if (err) throw err;
                    res.json({
                        token,
                        user: {
                            id: user.id,
                            email: user.email,
                            username: user.username
                        }
                    });
                }
            );
        });
    });
});

// Home route
app.get('/', (req, res) => {
    res.send('Server is running!');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
