// Import dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors=require('cors')
require('dotenv').config();

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors())

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Models
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
});

const FoodSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    imageUrl: { type: String, required: true },
    description: { type: String, required: true },
});

const User = mongoose.model('DeepuUser', UserSchema);
const Food = mongoose.model('DeepuFood', FoodSchema);

// Middleware to verify JWT
const authenticate = (request, response, next) => {
    let jwtToken;
    const authHeader = request.headers["authorization"];
    // console.log(authHeader)
    if (authHeader !== undefined) {
      jwtToken = authHeader.split(" ")[1];
      console.log(jwtToken)
    }
    if (jwtToken === undefined) {
      response.status(401);
      response.send("Invalid JWT Token");
    } else {
      jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
        if (error) {
          response.status(401);
          response.send("Invalid JWT Token");
        } else {
            request.user = payload;
          next();
        }
      });
    }
  };

// Middleware to verify admin access
const verifyAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Routes

// Admin login API
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;

    // Admin credentials
    const adminCredentials = {
        email: 'admin@foodwebsite.com',
        password: 'admin123', // hashed for demonstration
    };

    if (email !== adminCredentials.email || password !== adminCredentials.password) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ email, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ adminToken:token });
});

// User signup API
app.post('/api/signup', async (req, res) => {
    const { email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error });
    }
});

// User login API
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ email, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error });
    }
});

// Add food item (Admin only)
app.post('/api/foods', async (req, res) => {
    const { name, price, imageUrl, description } = req.body;

    try {
        const newFood = new Food({ name, price, imageUrl, description });
        await newFood.save();
        res.status(201).json({ message: 'Food item added successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error adding food item', error });
    }
});
// Get all food items
app.get('/api/foods', async (req, res) => {
    try {
        const foods = await Food.find();
        res.json(foods);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching food items', error });
    }
});

// Proceed to buy (dummy payment handling)
app.post('/api/foods/buy', authenticate, async (req, res) => {
    res.json({ message: 'Payment successful! Your order is being processed.' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
