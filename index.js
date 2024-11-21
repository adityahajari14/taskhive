// server.js
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "your_session_secret",
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Database schema setup
async function setupDatabase() {
  const client = await db.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );

      CREATE TABLE IF NOT EXISTS focus_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        duration INTEGER NOT NULL,
        type VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS habits (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        completed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS todos (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        title VARCHAR(255) NOT NULL,
        deadline DATE,
        completed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Database schema set up successfully');
  } catch (error) {
    console.error('Error setting up database schema:', error);
  } finally {
    client.release();
  }
}

setupDatabase();

// Passport configuration
passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, user)
            } else {
              return cb(null, false)
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

// Middleware to check if user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("Success");
            res.redirect("/");
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
}));

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).render('error', { message: 'Error logging out' });
    }
    res.redirect('/');
  });
});

app.get("/focus-timer", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM focus_sessions WHERE user_id = $1', [req.user.id]);
    res.render("focus-timer", { user: req.user, sessions: result.rows });
  } catch (error) {
    res.status(500).render('error', { message: 'Error fetching focus sessions' });
  }
});

app.post("/focus-timer/sessions", ensureAuthenticated, async (req, res) => {
  try {
    const { duration, type } = req.body;
    await db.query('INSERT INTO focus_sessions (user_id, duration, type) VALUES ($1, $2, $3)', [req.user.id, duration, type]);
    res.redirect("/focus-timer");
  } catch (error) {
    res.status(500).render('error', { message: 'Error adding focus session' });
  }
});

app.get("/habit-tracker", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM habits WHERE user_id = $1', [req.user.id]);
    res.render("habit-tracker", { user: req.user, habits: result.rows });
  } catch (error) {
    res.status(500).render('error', { message: 'Error fetching habits' });
  }
});

app.post("/habit-tracker/habits", ensureAuthenticated, async (req, res) => {
  try {
    const { name } = req.body;
    await db.query('INSERT INTO habits (user_id, name) VALUES ($1, $2)', [req.user.id, name]);
    res.redirect("/habit-tracker");
  } catch (error) {
    res.status(500).render('error', { message: 'Error adding habit' });
  }
});

app.post("/habit-tracker/habits/:id/toggle", ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query('UPDATE habits SET completed = NOT completed WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    res.redirect("/habit-tracker");
  } catch (error) {
    res.status(500).render('error', { message: 'Error updating habit' });
  }
});

app.post("/habit-tracker/habits/:id/delete", ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query('DELETE FROM habits WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    res.redirect("/habit-tracker");
  } catch (error) {
    res.status(500).render('error', { message: 'Error deleting habit' });
  }
});

app.get("/todo-list", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM todos WHERE user_id = $1', [req.user.id]);
    res.render("todo-list", { user: req.user, todos: result.rows });
  } catch (error) {
    res.status(500).render('error', { message: 'Error fetching todos' });
  }
});

app.post("/todo-list/todos", ensureAuthenticated, async (req, res) => {
  try {
    const { title, deadline} = req.body;
    const safeDeadline = deadline || null;
    await db.query('INSERT INTO todos (user_id, title, deadline) VALUES ($1, $2, $3)', [req.user.id, title, safeDeadline]);
    res.redirect("/todo-list");
  } catch (error) {
    res.status(500).render('error', { message: 'Error adding todo' });
  }
});

app.post("/todo-list/todos/:id/toggle", ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query('UPDATE todos SET completed = NOT completed WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    res.redirect("/todo-list");
  } catch (error) {
    res.status(500).render('error', { message: 'Error updating todo' });
  }
});

app.post("/todo-list/todos/:id/delete", ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    await db.query('DELETE FROM todos WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    res.redirect("/todo-list");
  } catch (error) {
    res.status(500).render('error', { message: 'Error deleting todo' });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});