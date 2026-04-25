require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const redis = require('redis');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const cron = require('node-cron'); // NEW: For automation
const app = express();
app.use(express.json());
app.use(cors());
// --- 1. Configuration & Validation ---
const PORT = process.env.PORT || 2000;
const SALT_ROUNDS = 12; // Production standard for bcrypt
const JWT_SECRET = process.env.CUSTOM_JWT_SECRET;
const PYTHON_SERVER_URL = process.env.PYTHON_SERVER_URL || "http://localhost:5000/hourly-monitor";
const HOURLY_MONITOR_URL = "http://localhost:5000/hourly-monitor"; // NEW

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

// --- 4. NEW: HOURLY SYNC LOGIC ---

/**
 * Automatically fetches data from Python, stores in Supabase for history, 
 * and Redis for the live dashboard.
 */
/*
const syncHourlyCalamityData = async () => {
  console.log(`[${new Date().toISOString()}] Starting Automated Hourly Sync...`);
  
  // Default BBox for the region if not specified
  const defaultBbox = [-26.1, 44.4, -26.0, 44.5];

  try {
    // A. Call Python Hourly Monitor
    const response = await axios.post(HOURLY_MONITOR_URL, { bbox: defaultBbox });
    const reportData = response.data;

    // B. Save to Supabase (Historical Archive)
    // Ensure you have a table named 'analysis_reports'
    const { error: dbError } = await supabase
      .from('analysis_reports')
      .insert([{
        area_name: reportData.area?.name || "Unknown",
        max_risk: reportData.stats?.find(s => s.id === 'max-risk')?.value || 0,
        full_report: reportData, // JSONB Column
        created_at: new Date()
      }]);

    if (dbError) throw dbError;

    // C. Save to Redis (Latest Snapshot for Dashboard)
    // Expire in 65 mins to ensure overlap with next cron run
    await redisClient.setEx('latest_dashboard_snapshot', 3900, JSON.stringify(reportData));

    console.log("✅ Hourly Sync Successful: Data archived and cached.");
  } catch (err) {
    console.error("❌ Hourly Sync Failed:", err.message);
  }
};*/
// Helper function to create a delay
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const syncHourlyCalamityData = async () => {
  console.log(`[${new Date().toISOString()}] Starting Automated Hourly Sync for ALL fields...`);

  try {
    // 1. Fetch all fields from Supabase
    // We need the ID, user_id, and the bounds (coordinates)
    const { data: fields, error: fetchError } = await supabase
      .from('fields')
      .select('id, user_id, name, bounds');

    if (fetchError) throw fetchError;

    if (!fields || fields.length === 0) {
      console.log("No fields found in database. Exiting sync.");
      return;
    }

    console.log(`Found ${fields.length} fields. Beginning sequential processing...`);

    // 2. Loop through each field sequentially
    // NOTE: We use 'for...of' instead of 'forEach' so 'await' works correctly
    for (const field of fields) {
      try {
        console.log(`📡 Analyzing field: ${field.name} (${field.id})...`);

        // Check if field has bounds; if not, skip or use default
        const bbox = [field.bounds.minlat, field.bounds.minlon, field.bounds.maxlat, field.bounds.maxlon]; 
        if (!bbox) {
          console.log(`⚠️ Skipping ${field.name}: No bounding box found.`);
          continue; 
        }

        // A. Call Python Engine for THIS specific field
        const response = await axios.post(HOURLY_MONITOR_URL, { bbox: bbox });
        const analysisResult = response.data;

        // B. Save to 'field_analyses' (NOT analysis_reports)
        // We use the specific table for individual farms
        const { error: dbError } = await supabase
          .from('field_analyses')
          .upsert({ 
            field_id: field.id, 
            user_id: field.user_id, 
            result_json: analysisResult,
            processed_at: new Date()
          });

        if (dbError) throw dbError;

        // C. Save to Redis using the specific Field ID
        // This matches your manual analysis route cache key!
        const cacheKey = `analysis:${field.id}`;
        await redisClient.setEx(cacheKey, 3900, JSON.stringify(analysisResult));

        console.log(`✅ Success: ${field.name} archived and cached.`);

        // D. The Anti-Crash Throttler
        // Wait 2.5 seconds before hitting Python with the next field
        await sleep(2500); 

      } catch (fieldError) {
        // If one field fails (e.g., Python timeout), log it but KEEP GOING
        console.error(`❌ Failed to process ${field.name}:`, fieldError.message);
      }
    }

    console.log("🏁 Global Hourly Sync Completed for all fields!");

  } catch (err) {
    console.error("❌ Global Hourly Sync Failed entirely:", err.message);
  }
};

// CRON JOB: Runs at minute 0 of every hour
cron.schedule('0 * * * *', () => {
  syncHourlyCalamityData();
});

// --- 5. Auth Routes (Production Flow) ---

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
// --- 6. Data Route: Python Integration + Redis Cache ---

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

// --- 7. NEW: Dashboard Data Route ---

/**
 * Fetches the latest hourly report. 
 * High performance because it checks Redis first.
 */
app.get('/api/dashboard/latest', authenticateToken, async (req, res) => {
  try {
    // Try Redis first
    const cached = await redisClient.get('latest_dashboard_snapshot');
    if (cached) {
      return res.json({ source: 'cache', report: JSON.parse(cached) });
    }

    // Fallback: Get most recent from Supabase
    const { data, error } = await supabase
      .from('analysis_reports')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !data) return res.status(404).json({ error: "No data available." });
    console.log(error);
    console.log(data);
    console.log(data);
    res.json({ source: 'database', report: data.full_report });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Error fetching dashboard data." });
  }
});

// --- 8. Existing Analysis Route ---
app.post('/api/field/analyze', authenticateToken, async (req, res) => {
  const { fieldId, bbox } = req.body;
  const cacheKey = `analysis:${fieldId}`;

  try {
    // A. Check Redis (Cache Hit)
    const cachedAnalysis = await redisClient.get(cacheKey);
    if (cachedAnalysis) {
      return res.json({ source: 'cache', data: JSON.parse(cachedAnalysis) });
    }

    // B. Call Python Service (Cache Miss)
    const pyResponse = await axios.post(PYTHON_SERVER_URL, { 
      bbox: bbox,
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
    console.log(err)
    res.status(500).json({ error: "Processing engine unreachable." });
  }
});
app.get('/api/fields/dashboard', authenticateToken, async (req, res) => {
  try {
    // req.user.id comes from your authenticateToken middleware
    const userId = req.user.id; 
    console.log("Dashboard Request for user_id:", userId);
    // 1. Fetch all basic fields for this   specific user
    const { data: fields, error: fieldsError } = await supabase
      .from('fields')
      .select('*')
      .eq('user_id', userId);

    if (fieldsError) throw fieldsError;
    console.log(fields);
    // If the user hasn't added any farms yet, return an empty array
    if (!fields || fields.length === 0) {
      return res.json({ data: [] });
    }

    // 2. Loop through the fields and attach the latest AI analysis
    // We use Promise.all so it checks Redis for all fields simultaneously (super fast)
    const dashboardData = await Promise.all(fields.map(async (field) => {
      const cacheKey = `analysis:${field.id}`;
      let analysisData = null;

      // A. Try to get the fast data from Redis first
      const cachedAnalysis = await redisClient.get(cacheKey);
      
      if (cachedAnalysis) {
        analysisData = JSON.parse(cachedAnalysis);
      } else {
        // B. CACHE MISS: Fallback to Supabase to find the most recent analysis
        const { data: dbAnalysis, error: dbError } = await supabase
          .from('field_analyses')
          .select('result_json')
          .eq('field_id', field.id)
          .order('processed_at', { ascending: false })
          .limit(1)
          .single(); // Gets only the top row

        // If we found it in the database, use it (and optionally re-cache it)
        if (!dbError && dbAnalysis) {
          analysisData = dbAnalysis.result_json;
          // Put it back in Redis so the next page load is fast
          await redisClient.setEx(cacheKey, 3900, JSON.stringify(analysisData));
        }
      }

      // Combine the field data with its AI analysis
      return {
        id: field.id,
        name: field.name,
        crop_type: field.crop_type,
        geometry: field.geometry,
        bounds: field.bounds,
        created_at: field.created_at,
        latest_analysis: analysisData // Will be null if it hasn't been analyzed yet
      };
    }));

    // 3. Send the fully constructed dashboard payload to the frontend
    res.json({ data: dashboardData });

  } catch (err) {
    console.error("Dashboard Route Error:", err.message);
    res.status(500).json({ error: "Failed to load fields and analysis data." });
  }
});

app.listen(PORT, () => {
  console.log(`Gateway running on http://localhost:${PORT}`);
  // Optional: Run a sync immediately on startup so Redis isn't empty
  // syncHourlyCalamityData(); 
  syncHourlyCalamityData();
});