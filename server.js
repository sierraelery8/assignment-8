const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session'); // 
const { db, User, Project, Task } = require('./database/setup');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Session middleware (after json middleware)
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecret', // should be stored in .env
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // set true if using https
}));

// Test database connection
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}
testConnection();


// AUTHENTICATION MIDDLEWARE

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        req.user = { id: req.session.userId, email: req.session.userEmail };
        return next();
    }
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
}


// USER REGISTRATION

app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: "Username, email, and password are required." });
        }

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) return res.status(400).json({ error: "Email already in use." });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({ username, email, password: hashedPassword });

        res.status(201).json({ message: "User registered successfully.", userId: newUser.id });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user.' });
    }
});


// USER LOGIN

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: "Email and password are required." });

        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ error: "Invalid email or password." });

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(401).json({ error: "Invalid email or password." });

        // Create session
        req.session.userId = user.id;
        req.session.userEmail = user.email;

        res.json({ message: "Login successful." });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Failed to log in.' });
    }
});


// USER LOGOUT

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error logging out:', err);
            return res.status(500).json({ error: 'Failed to log out.' });
        }
        res.json({ message: 'Logout successful.' });
    });
});


// PROTECTED PROJECT ROUTES


// GET /api/projects - Get all projects (only authenticated users)
app.get('/api/projects', isAuthenticated, async (req, res) => {
    try {
        const projects = await Project.findAll({ where: { userId: req.user.id } });
        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});


// TASK ROUTES

// GET /api/tasks - Get all tasks (public for now)
app.get('/api/tasks', async (req, res) => {
    try {
        const tasks = await Task.findAll();
        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// START SERVER

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
