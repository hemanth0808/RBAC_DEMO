const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require('dotenv');
const authMiddleware = require("./middleware/auth");
const roleMiddleware = require("./middleware/roles");
const sql = require("mssql");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const logger = require("./utils/logger");  // Import logger

dotenv.config();
const app = express();
app.use(express.json());
app.use(helmet());  // Add Helmet
app.use(cors({
    origin: "http://localhost:5000", // Add the correct origin of your Swagger UI
  }));    // Add CORS

// Rate Limiting Middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Swagger Setup
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const swaggerOptions = {
  swaggerDefinition: {
    openapi: "3.0.0",
    info: {
      title: "RBAC API",
      version: "1.0.0",
      description: "API documentation for the RBAC system",
    },
    servers: [{ url: "http://localhost:5000" }],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
  apis: ["./app.js"], 
};
const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

const config = {
  server:process.env.SERVER?? "DESKTOP-55H7L9D",
  database: process.env.DB??"RBAC",
  user: process.env.USER??"sqluser", 
  password: process.env.PASSWORD??"sqluser",
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
};

// Centralized Database Pooling
const poolPromise = new sql.ConnectionPool(config)
  .connect()
  .then((pool) => {
    logger.info("Connected to SQL Server");
    return pool;
  })
  .catch((err) => {
    logger.error("Database Connection Failed!", err);
  });

// Function to execute queries
async function executeQuery(query, params = []) {
  try {
    const pool = await poolPromise;
    const request = pool.request();
    params.forEach((param) =>
      request.input(param.name, param.type, param.value)
    );
    const result = await request.query(query);
    return result.recordset;
  } catch (err) {
    throw err;
  }
}

/**
 * @swagger
 * /:
 *   get:
 *     summary: Home page
 *     description: Returns a welcome message for the home page.
 *     responses:
 *       200:
 *         description: Welcome message returned successfully.
 */
app.get("/", async (req, res) => {
  return res.status(200).json({ message: "This is the home page" });
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     description: Registers a user with a default role of 'User'.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User registered successfully.
 *       400:
 *         description: Error occurred during registration.
 */
app.post("/register", async (req, res) => {
  const { username, password } = req.body; // Removed 'role'
  try {
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `
      INSERT INTO Users (Username, PasswordHash, Role)
      VALUES (@username, @password, 'User') -- Default role set to 'User'
    `;
    await executeQuery(query, [
      { name: "username", type: sql.NVarChar, value: username },
      { name: "password", type: sql.NVarChar, value: hashedPassword },
    ]);
    res.json({ message: "User registered successfully" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/**
 * @swagger
 * /create-user:
 *   post:
 *     summary: Create a new user (Admin only)
 *     description: Allows an Admin to create users with specified roles.
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *     responses:
 *       200:
 *         description: User created successfully.
 *       400:
 *         description: Error occurred while creating the user.
 */
app.post(
  "/create-user",
  authMiddleware, // Ensure the user is authenticated
  roleMiddleware(["Admin"]), // Only allow Admins to access this route
  async (req, res) => {
    const { username, password, role } = req.body;
    const allowedRoles = ["User", "Moderator", "Admin"];
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: "Invalid role specified" });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const query = `
        INSERT INTO Users (Username, PasswordHash, Role)
        VALUES (@username, @password, @role)
      `;
      await executeQuery(query, [
        { name: "username", type: sql.NVarChar, value: username },
        { name: "password", type: sql.NVarChar, value: hashedPassword },
        { name: "role", type: sql.NVarChar, value: role },
      ]);
      res.json({ message: `${role} user created successfully` });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

/**
 * @swagger
 * /login:
 *   post:
 *     summary: User login
 *     description: Logs in a user and returns a JWT token.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful, returns JWT token.
 *       400:
 *         description: Invalid credentials.
 */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = `SELECT * FROM Users WHERE Username = @username`;
    const users = await executeQuery(query, [
      { name: "username", type: sql.NVarChar, value: username },
    ]);

    if (users.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.PasswordHash);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.UserID, role: user.Role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * @swagger
 * /admin:
 *   get:
 *     summary: Admin page
 *     description: Access restricted to Admin users.
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Welcome, Admin.
 *       403:
 *         description: Access forbidden.
 */
app.get("/admin", authMiddleware, roleMiddleware(["Admin"]), (req, res) => {
  res.json({ message: "Welcome, Admin!" });
});

/**
 * @swagger
 * /moderator:
 *   get:
 *     summary: Moderator page
 *     description: Access restricted to Moderator and Admin users.
 *     tags: [Moderator]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Welcome, Moderator.
 *       403:
 *         description: Access forbidden.
 */
app.get("/moderator", authMiddleware, roleMiddleware(["Moderator", "Admin"]), (req, res) => {
    res.json({ message: "Welcome, Moderator!" });
});

/**
 * @swagger
 * /user:
 *   get:
 *     summary: User page
 *     description: Access restricted to all authenticated users.
 *     tags: [User]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Welcome message for the user.
 *       403:
 *         description: Access forbidden.
 */
app.get("/user", authMiddleware, roleMiddleware(["User", "Moderator", "Admin"]), (req, res) => {
    res.json({ message: `Welcome, ${req.user.role}!` });
});

/**
 * @swagger
 * /usersList:
 *   get:
 *     summary: List all users
 *     description: Access restricted to Admin users only.
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Returns a list of all users.
 *       403:
 *         description: Access forbidden.
 */
app.get("/usersList",authMiddleware,roleMiddleware(["Admin"]), async (req, res) => {
    try {
      const pool = await sql.connect(config);
      const result = await pool.request().query("SELECT * FROM Users");
      res.json(result.recordset);
    } catch (err) {
      console.error("Database query failed:", err);
      res.status(500).send("Internal Server Error");
    } finally {
      sql.close();
    }
  }
);

const PORT = process.env.PORT ?? 5000;
app.listen(PORT,"0.0.0.0", () => console.log(`Server running on port ${PORT}`));
