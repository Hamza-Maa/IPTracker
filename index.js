const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Load service account key
const serviceAccount = require("./serviceAccountKey.json");

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// Helper: Get client's IP address
const getClientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  return forwarded ? forwarded.split(",")[0] : req.connection.remoteAddress;
};

// POST /get-ip: Verify token, get IP, register user, and store IP
app.post("/get-ip", async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ error: "Missing ID token" });
  }

  try {
    // Verify ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;

    // Get user info from Firebase Auth
    const userRecord = await admin.auth().getUser(uid);
    const email = userRecord.email;

    // Check if user exists in 'users' collection
    const userDocRef = db.collection("users").doc(uid);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      // Create new user doc
      await userDocRef.set({
        uid,
        email,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    // Get client IP
    const ip = getClientIp(req);

    // Store IP info
    await db.collection("user_ips").doc(uid).set({
      ip,
      lastLogin: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ uid, email, ip });
  } catch (error) {
    console.error("Error in /get-ip:", error);
    res.status(401).json({ error: "Invalid ID token or internal error" });
  }
});

// GET /get-ip-by-uid/:uid - Get IP info by UID
app.get("/get-ip-by-uid/:uid", async (req, res) => {
  const { uid } = req.params;

  if (!uid) {
    return res.status(400).json({ error: "Missing UID" });
  }

  try {
    const docRef = db.collection("user_ips").doc(uid);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "No IP data found for this UID" });
    }

    res.json({ uid, ...doc.data() });
  } catch (error) {
    console.error("Error fetching IP data:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
