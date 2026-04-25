require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const redis = require('redis');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());
// --- 1. Configuration & Validation ---
const PORT = process.env.PORT || 2000;
const SALT_ROUNDS = 12; // Production standard for bcrypt
const JWT_SECRET = process.env.CUSTOM_JWT_SECRET;
const PYTHON_SERVER_URL = process.env.PYTHON_SERVER_URL || "http://localhost:5000/analyze";

if (!JWT_SECRET) {
  console.error("FATAL: CUSTOM_JWT_SECRET is not defined in .env");
  process.exit(1);
}

// --- 2. Database & Cache Clients ---
// Note: Use Service Role Key for backend bypass of RLS if necessary
const supabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY
);

const redisClient = redis.createClient({ url: process.env.REDIS_URL });
redisClient.on('error', (err) => console.log('Redis Client Error', err));
redisClient.connect().then(() => console.log('Connected to Redis'));

// --- 3. Middleware: Auth Shield ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token." });
    req.user = user;
    next();
  });
};

// --- 4. Auth Routes (Production Flow) ---

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, companyName,country } = req.body;

    // Check if user already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (existingUser) return res.status(400).json({ error: "User already registered." });

    // Hash the password properly
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Save to custom table
    const { data: newUser, error } = await supabase
      .from('users')
      .insert([{ email, password: hashedPassword, name, companyName, country }])
      .select('id, email, name, companyName, country')
      .single();

    if (error) throw error;

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ user: newUser, token });

  } catch (err) {
    res.status(500).json({ error: "Error creating account." });
    console.log(err);
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) return res.status(401).json({ error: "Invalid email or password." });

    // Compare bcrypt hash
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid email or password." });

    // Sign JWT
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      user: { id: user.id, email: user.email, name: user.name, companyName: user.companyName, country: user.country },
      token
    });

  } catch (err) {
    res.status(500).json({ error: "Authentication failed." });
    console.log(err);
  }
});


app.post('/api/fields/import', authenticateToken, async (req, res) => {
  const field = req.body; 

  // Extract the specific metadata sent from the frontend's 'tags' object
  const fieldName = field.name;
  const cropType = field.cropType;

  // Updated validation to ensure the flattened data exists
  if (!field || !field.id || !field.geometry || !fieldName || !cropType) {
    console.log(field,field.id,field.geometry,fieldName,cropType)
    return res.status(400).json({ 
      error: "Invalid data format. ID, geometry, name, and crop type are required." 
    });
  }

  try {
    // Construct the single, flattened record to insert based on the new SQL schema
    const userId = req.user.id; // Extracted safely via your JWT middleware
    
    const dataToInsert = {
      id: field.id,
      user_id: userId,          // Links directly to public.users(id)
      name: fieldName,          // Flattened from tags.name
      crop_type: cropType,      // Flattened from tags.crop
      geometry: field.geometry, // Used by Leaflet to redraw the shape
      bounds: field.bounds      // Used to zoom the map to the correct area
    };

    const { data, error } = await supabase
      .from('fields')
      .insert(dataToInsert) 
      .select()
      .single(); 

    if (error) throw error;

    res.status(201).json({ 
      message: "Field successfully imported", 
      field: data 
    });

  } catch (err) {
    console.error("Import Error:", err.message);
    res.status(500).json({ error: "Failed to import field data." });
  }
});


app.get('/api/fields', authenticateToken, async (req, res) => {
  try {
    console.log("Decoded JWT payload:", req.user);
    console.log("Searching database for user_id:", req.user.id);
    // 1. Get the securely verified user ID from the JWT middleware
    const userId = req.user.id; 

    // 2. Query Supabase for all fields matching this user_id
    const { data, error } = await supabase
      .from('fields')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false }); // Puts the newest fields first
    console.log(data);
    // 3. Handle database errors
    if (error) {
      console.error("Database Fetch Error:", error.message);
      console.log(error);
      return res.status(500).json({ error: "Failed to fetch fields." });
    }

    // 4. Return the fields to the frontend
    res.status(200).json({ fields: data });

  } catch (err) {
    console.log(err);
    console.error("Server Error:", err.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// --- 5. Data Route: Python Integration + Redis Cache ---

// ROUTE 3: Delete a field
app.delete('/api/fields/:id', authenticateToken, async (req, res) => {
  try {
    const fieldId = req.params.id;
    const userId = req.user.id; // Security: Ensure they only delete THEIR fields

    const { error } = await supabase
      .from('fields')
      .delete()
      .eq('id', fieldId)
      .eq('user_id', userId);

    if (error) throw error;
    
    res.status(200).json({ message: "Field deleted successfully" });
  } catch (err) {
    console.error("Delete Error:", err.message);
    res.status(500).json({ error: "Failed to delete field." });
  }
});

app.post('/api/field/analyze', authenticateToken, async (req, res) => {
  const { fieldId, coordinates } = req.body;
  const cacheKey = `analysis:${fieldId}`;

  try {
    // A. Check Redis (Cache Hit)
    const cachedAnalysis = await redisClient.get(cacheKey);
    if (cachedAnalysis) {
      return res.json({ source: 'cache', data: JSON.parse(cachedAnalysis) });
    }

    // B. Call Python Service (Cache Miss)
    const pyResponse = await axios.post(PYTHON_SERVER_URL, { 
      coords: coordinates,
      user_id: req.user.id 
    }, { timeout: 10000 }); // 10s timeout for heavy processing

    const analysisResult = pyResponse.data;

    // C. Save to Supabase (Persistence)
    const { error: dbError } = await supabase
      .from('field_analyses')
      .upsert({ 
        field_id: fieldId, 
        user_id: req.user.id, 
        result_json: analysisResult,
        processed_at: new Date()
      });

    if (dbError) console.error("Supabase Save Error:", dbError);

    // D. Save to Redis (Set to expire in 24 hours)
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(analysisResult));

    res.json({ source: 'python_engine', data: analysisResult });

  } catch (err) {
    console.error("Analysis Pipeline Error:", err.message);
    res.status(500).json({ error: "Processing engine unreachable." });
  }
});

app.listen(PORT, () => console.log(`Gateway running on http://localhost:${PORT}`));