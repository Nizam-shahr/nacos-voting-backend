const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Initialize Firebase Admin
const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

// Improved IP address tracking - Extract only the client IP
app.use((req, res, next) => {
  let clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;
  
  console.log('Raw IP info:', {
    'x-forwarded-for': req.headers['x-forwarded-for'],
    'connection.remoteAddress': req.connection.remoteAddress,
    'socket.remoteAddress': req.socket.remoteAddress
  });

  // Handle multiple IPs in x-forwarded-for (common with proxies)
  if (clientIp && clientIp.includes(',')) {
    // Take the first IP which is the original client IP
    clientIp = clientIp.split(',')[0].trim();
  }
  
  // Remove IPv6 prefix if present
  if (clientIp && clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7);
  }

  // Fallback for invalid IPs
  if (!clientIp || clientIp === '::1') {
    clientIp = 'unknown';
  }
  
  req.clientIp = clientIp;
  console.log('Final client IP:', clientIp);
  next();
});

// Generate device fingerprint
const generateDeviceFingerprint = (req) => {
  const fingerprintData = {
    userAgent: req.headers['user-agent'] || 'unknown',
    accept: req.headers['accept'] || 'unknown',
    acceptLanguage: req.headers['accept-language'] || 'unknown',
    acceptEncoding: req.headers['accept-encoding'] || 'unknown',
    sec_ch_ua: req.headers['sec-ch-ua'] || 'unknown',
    sec_ch_ua_platform: req.headers['sec-ch-ua-platform'] || 'unknown',
    sec_ch_ua_mobile: req.headers['sec-ch-ua-mobile'] || 'unknown'
  };

  // Create a hash of the fingerprint data
  const fingerprintString = JSON.stringify(fingerprintData);
  const fingerprintHash = crypto.createHash('md5').update(fingerprintString).digest('hex');
  
  console.log('🔍 Device Fingerprint:', {
    hash: fingerprintHash,
    data: fingerprintData,
    ip: req.clientIp
  });
  
  return {
    hash: fingerprintHash,
    data: fingerprintData,
    combined: `${req.clientIp}_${fingerprintHash}`
  };
};

// STRICT Device checking - IP + Fingerprint
const checkDeviceUsed = async (ipAddress, fingerprint) => {
  try {
    console.log('🔍 STRICT Device Check:', { ip: ipAddress, fingerprint: fingerprint.hash });
    
    const users = await db.collection('Users').get();
    let deviceFound = false;
    let foundUserEmail = '';
    let matchType = '';

    users.docs.forEach(doc => {
      const userData = doc.data();
      
      // Check 1: Exact same device (IP + Fingerprint)
      if (userData.deviceFingerprint && userData.deviceFingerprint.combined === fingerprint.combined) {
        deviceFound = true;
        foundUserEmail = userData.institutionalEmail;
        matchType = 'EXACT_DEVICE';
        console.log('🚫 Exact device match found:', foundUserEmail);
        return;
      }
      
      // Check 2: Same IP but different device
      if (userData.ipAddress === ipAddress) {
        deviceFound = true;
        foundUserEmail = userData.institutionalEmail;
        matchType = 'SAME_NETWORK';
        console.log('🚫 Same network IP found:', foundUserEmail);
        return;
      }
      
      // Check 3: Same fingerprint but different IP (user switched networks)
      if (userData.deviceFingerprint && userData.deviceFingerprint.hash === fingerprint.hash) {
        deviceFound = true;
        foundUserEmail = userData.institutionalEmail;
        matchType = 'SAME_DEVICE_DIFFERENT_NETWORK';
        console.log('🚫 Same device, different network:', foundUserEmail);
        return;
      }
    });

    return { deviceFound, foundUserEmail, matchType };
  } catch (error) {
    console.error('Error checking device:', error);
    return { deviceFound: false, foundUserEmail: '', matchType: '' };
  }
};

// Check for duplicate personal email
const checkDuplicatePersonalEmail = async (personalEmail) => {
  try {
    console.log('🔍 Checking personal email:', personalEmail);
    
    const users = await db.collection('Users').get();
    let duplicateFound = false;
    let duplicateEmail = '';

    users.docs.forEach(doc => {
      const userData = doc.data();
      
      // Check if personal email matches ANY user
      if (userData.personalEmail && userData.personalEmail.toLowerCase() === personalEmail.toLowerCase()) {
        duplicateFound = true;
        duplicateEmail = userData.institutionalEmail;
        console.log('🚫 Personal email already used by:', duplicateEmail);
      }
    });

    return { duplicateFound, duplicateEmail };
  } catch (error) {
    console.error('Error checking personal email:', error);
    return { duplicateFound: false, duplicateEmail: '' };
  }
};

// Generate session token
const generateSessionToken = () => {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
};

// Session verification middleware
const verifySession = async (req, res, next) => {
  const { institutionalEmail, sessionToken } = req.body;
  
  if (!institutionalEmail || !sessionToken) {
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }

  try {
    const userDocs = await db.collection('Users')
      .where('institutionalEmail', '==', institutionalEmail.toLowerCase())
      .where('sessionToken', '==', sessionToken)
      .where('sessionExpiry', '>', admin.firestore.Timestamp.now())
      .get();

    if (userDocs.empty) {
      return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
    }

    req.user = userDocs.docs[0].data();
    req.userId = userDocs.docs[0].id;
    next();
  } catch (error) {
    res.status(500).json({ error: 'Session verification failed' });
  }
};

// Enhanced Sign In with STRICT IP + FINGERPRINT restriction
app.post('/api/sign-in', async (req, res) => {
  const { institutionalEmail, personalEmail, matricNumber, fullName } = req.body;
  
  if (!institutionalEmail || !matricNumber || !fullName || !personalEmail) {
    return res.status(400).json({ error: 'All fields are required: institutional email, personal email, matric number, and full name' });
  }

  // Validate institutional email format
  const institutionalEmailRegex = /^(22|23|24)03(cyb|sen|ins|cmp)\d{3}@alhikmah\.edu\.ng$/i;
  if (!institutionalEmailRegex.test(institutionalEmail.toLowerCase())) {
    return res.status(400).json({ 
      error: 'Invalid institutional email format. Must be: 2203sen001@alhikmah.edu.ng' 
    });
  }

  // Validate personal email format
  const personalEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!personalEmailRegex.test(personalEmail.toLowerCase())) {
    return res.status(400).json({ error: 'Invalid personal email format' });
  }

  // Validate full name has at least first and last name
  const nameParts = fullName.trim().split(' ').filter(part => part.length > 1);
  if (nameParts.length < 2) {
    return res.status(400).json({ error: 'Please enter your complete first and last name' });
  }

  // Extract details from institutional email for validation
  const emailParts = institutionalEmail.toLowerCase().split('@')[0];
  const year = emailParts.substring(0, 2);
  const department = emailParts.substring(4, 7);

  // Validate matric number format
  const matricRegex = /^(22|23|24)\/03(cyb|sen|ins|cmp)\d{3}$/i;
  if (!matricRegex.test(matricNumber)) {
    return res.status(400).json({ error: 'Invalid matric number format' });
  }

  const matricParts = matricNumber.toLowerCase().split('/');
  const matricYear = matricParts[0];
  const matricDept = matricParts[1].substring(2, 5);

  if (year !== matricYear) {
    return res.status(400).json({ error: 'Year in email and matric number do not match' });
  }

  if (department !== matricDept) {
    return res.status(400).json({ error: 'Department in email and matric number do not match' });
  }

  const normalizedInstitutionalEmail = institutionalEmail.toLowerCase();
  const normalizedPersonalEmail = personalEmail.toLowerCase();
  const normalizedMatric = matricNumber.toLowerCase();
  const normalizedName = fullName.trim();

  try {
    console.log('🔄 Sign-in attempt from IP:', req.clientIp, 'for:', institutionalEmail);

    // Generate device fingerprint
    const deviceFingerprint = generateDeviceFingerprint(req);
    
    // STEP 1: STRICT Device Check (IP + Fingerprint)
    const { deviceFound, foundUserEmail, matchType } = await checkDeviceUsed(req.clientIp, deviceFingerprint);
    
    if (deviceFound) {
      let errorMessage = '';
      
      switch(matchType) {
        case 'EXACT_DEVICE':
          errorMessage = `🚫 THIS EXACT DEVICE HAS ALREADY VOTED 🚫

This specific phone/computer was already used by: ${foundUserEmail}

You cannot vote again from this same device, even with different credentials.`;
          break;
          
        case 'SAME_NETWORK':
          errorMessage = `🚫 THIS NETWORK HAS ALREADY BEEN USED 🚫

This internet connection (WiFi/network) was already used by: ${foundUserEmail}

💡 SOLUTION: Turn off WiFi and use your MOBILE DATA`;
          break;
          
        case 'SAME_DEVICE_DIFFERENT_NETWORK':
          errorMessage = `🚫 THIS DEVICE HAS ALREADY VOTED 🚫

This phone/computer was used from a different network by: ${foundUserEmail}

You need to use a completely different device to vote.`;
          break;
          
        default:
          errorMessage = `This device/network has already been used by: ${foundUserEmail}`;
      }
      
      console.log('🚫 Device blocked - Type:', matchType, 'User:', foundUserEmail);
      return res.status(400).json({ 
        error: errorMessage,
        deviceBlocked: true,
        blockType: matchType
      });
    }

    // STEP 2: Check for duplicate personal email
    const { duplicateFound, duplicateEmail } = await checkDuplicatePersonalEmail(normalizedPersonalEmail);
    
    if (duplicateFound) {
      console.log('🚫 DUPLICATE PERSONAL EMAIL - Already used by:', duplicateEmail);
      return res.status(400).json({ 
        error: `This personal email (${normalizedPersonalEmail}) has already been used by another student (${duplicateEmail}). Each student must use their own unique personal email address.`,
        emailBlocked: true 
      });
    }

    // STEP 3: Check for existing user (by institutional email)
    const userDocs = await db.collection('Users')
      .where('institutionalEmail', '==', normalizedInstitutionalEmail)
      .get();

    let userData;
    let userId;
    let sessionToken = generateSessionToken();

    if (!userDocs.empty) {
      // EXISTING USER - But device is already blocked above, so this should rarely happen
      console.log('❌ Existing user but device already blocked');
      return res.status(400).json({ 
        error: 'Your account exists but this device/network has already been used by another student. Please use a different device and network.',
        deviceBlocked: true 
      });
    }

    // STEP 4: NEW USER CREATION (Device is clean)
    console.log('✅ Creating new user - Device is clean');
    const newUserRef = db.collection('Users').doc();
    userId = newUserRef.id;

    userData = {
      institutionalEmail: normalizedInstitutionalEmail,
      personalEmail: normalizedPersonalEmail,
      matricNumber: normalizedMatric,
      fullName: normalizedName,
      votedPositions: [],
      ipAddress: req.clientIp,
      deviceFingerprint: deviceFingerprint,
      userAgent: req.headers['user-agent'],
      sessionToken: sessionToken,
      sessionExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 2 * 60 * 60 * 1000)),
      signInTimestamp: admin.firestore.Timestamp.now(),
      voteTimestamp: null,
      createdAt: admin.firestore.Timestamp.now(),
      status: 'active'
    };

    await newUserRef.set(userData);

    const positions = await db.collection('Candidates').get();
    const allPositions = [...new Set(positions.docs.map(doc => doc.data().position))];

    return res.status(200).json({ 
      message: 'Sign-in successful', 
      institutionalEmail: normalizedInstitutionalEmail,
      personalEmail: normalizedPersonalEmail,
      matricNumber: normalizedMatric,
      fullName: normalizedName,
      remainingPositions: allPositions,
      sessionToken,
      continueVoting: false
    });

  } catch (error) {
    console.error('Sign-in error:', error);
    res.status(500).json({ error: 'Sign-in failed' });
  }
});

// Vote endpoint - Session verification only (device already checked during sign-in)
app.post('/api/vote', verifySession, async (req, res) => {
  const { institutionalEmail, candidateId, position } = req.body;

  if (!candidateId || !position) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const normalizedInstitutionalEmail = institutionalEmail.toLowerCase();

  try {
    await db.runTransaction(async (transaction) => {
      const userRef = db.collection('Users').doc(req.userId);
      const userDoc = await transaction.get(userRef);
      
      if (!userDoc.exists) {
        throw new Error('User not found');
      }

      const userData = userDoc.data();

      if (userData.votedPositions && userData.votedPositions.includes(position)) {
        throw new Error(`You have already voted for ${position}`);
      }

      const candidateDoc = await transaction.get(db.collection('Candidates').doc(candidateId));
      if (!candidateDoc.exists) {
        throw new Error('Candidate not found');
      }

      const candidateData = candidateDoc.data();
      if (candidateData.position !== position) {
        throw new Error('Candidate position mismatch');
      }

      // Record the vote
      const voteRef = db.collection('Votes').doc();
      transaction.set(voteRef, {
        candidateId,
        userId: req.userId,
        userInstitutionalEmail: normalizedInstitutionalEmail,
        position,
        ipAddress: req.clientIp,
        timestamp: admin.firestore.Timestamp.now(),
        userAgent: req.headers['user-agent']
      });

      transaction.update(userRef, {
        votedPositions: admin.firestore.FieldValue.arrayUnion(position),
        lastVoteTimestamp: admin.firestore.Timestamp.now(),
        lastVoteIp: req.clientIp,
        totalVotes: (userData.totalVotes || 0) + 1
      });
    });

    res.status(200).json({ 
      message: 'Vote submitted successfully',
      position: position
    });

  } catch (error) {
    console.error('Vote error:', error);
    res.status(400).json({ 
      error: 'Failed to submit vote', 
      details: error.message 
    });
  }
});

// Get positions
app.get('/api/positions', async (req, res) => {
  try {
    const candidates = await db.collection('Candidates').get();
    const positions = [...new Set(candidates.docs.map(doc => doc.data().position))].sort();
    res.status(200).json(positions);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch positions' });
  }
});

// Get candidates by position
app.get('/api/candidates/:position', async (req, res) => {
  try {
    const { position } = req.params;
    
    if (!position) {
      return res.status(400).json({ error: 'Position parameter is required' });
    }
    
    const query = db.collection('Candidates').where('position', '==', position);
    const candidates = await query.get();
    const candidateList = candidates.docs.map(doc => ({ 
      id: doc.id, 
      ...doc.data() 
    }));
    
    res.status(200).json(candidateList);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch candidates' });
  }
});

// Public results
app.get('/api/public/votes', async (req, res) => {
  try {
    const candidates = await db.collection('Candidates').get();
    const votes = await db.collection('Votes').get();
    
    const voteCounts = {};
    const totalVotes = votes.size;
    
    candidates.docs.forEach(candidateDoc => {
      const { name, position } = candidateDoc.data();
      if (!voteCounts[position]) voteCounts[position] = [];
      voteCounts[position].push({ name, votes: 0 });
    });
    
    votes.docs.forEach(vote => {
      const { candidateId, position } = vote.data();
      const candidateDoc = candidates.docs.find(c => c.id === candidateId);
      if (candidateDoc && candidateDoc.data().position === position) {
        const { name } = candidateDoc.data();
        const candidateInPosition = voteCounts[position].find(c => c.name === name);
        if (candidateInPosition) candidateInPosition.votes += 1;
      }
    });
    
    Object.keys(voteCounts).forEach(position => {
      voteCounts[position].sort((a, b) => b.votes - a.votes);
    });
    
    res.status(200).json({
      voteCounts,
      totalVotes,
      lastUpdated: new Date().toISOString()
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch vote results' });
  }
});

// Development votes table
app.get('/api/dev/votes-table', async (req, res) => {
  try {
    const votesSnapshot = await db.collection('Votes').get();
    const candidatesSnapshot = await db.collection('Candidates').get();
    const usersSnapshot = await db.collection('Users').get();
    
    const voteList = votesSnapshot.docs.map(doc => {
      const voteData = doc.data();
      const candidateDoc = candidatesSnapshot.docs.find(c => c.id === voteData.candidateId);
      const userDoc = usersSnapshot.docs.find(u => u.id === voteData.userId);
      
      // Handle Firebase timestamp properly
      let timestampValue = voteData.timestamp;
      let formattedTimestamp = 'N/A';
      let isoString = 'N/A';
      
      if (timestampValue) {
        // Convert Firebase Timestamp to JavaScript Date
        if (timestampValue.toDate) {
          const date = timestampValue.toDate();
          formattedTimestamp = date.toLocaleString();
          isoString = date.toISOString();
        } else if (timestampValue._seconds) {
          // Handle Firebase Timestamp structure
          const date = new Date(timestampValue._seconds * 1000);
          formattedTimestamp = date.toLocaleString();
          isoString = date.toISOString();
        } else if (typeof timestampValue === 'string') {
          const date = new Date(timestampValue);
          formattedTimestamp = date.toLocaleString();
          isoString = date.toISOString();
        }
      }
      
      return {
        id: doc.id,
        userInstitutionalEmail: voteData.userInstitutionalEmail || (userDoc ? userDoc.data().institutionalEmail : 'Unknown'),
        position: voteData.position,
        candidateName: candidateDoc ? candidateDoc.data().name : 'Unknown Candidate',
        timestamp: formattedTimestamp,
        rawTimestamp: isoString,
        firebaseTimestamp: timestampValue
      };
    });
    
    // Sort by timestamp descending (newest first)
    voteList.sort((a, b) => {
      const timeA = new Date(a.rawTimestamp);
      const timeB = new Date(b.rawTimestamp);
      return timeB - timeA;
    });
    
    res.status(200).json({
      votes: voteList,
      totalVotes: voteList.length,
      lastUpdated: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error fetching votes table:', error);
    res.status(500).json({ error: 'Failed to fetch votes table' });
  }
});

// Device analytics endpoint
app.get('/api/admin/device-analytics', async (req, res) => {
  try {
    const users = await db.collection('Users').get();
    const deviceStats = {
      totalUsers: users.size,
      uniqueIPs: new Set(),
      uniqueDevices: new Set(),
      devicesPerIP: {},
      ipNetworks: {}
    };

    users.docs.forEach(doc => {
      const userData = doc.data();
      deviceStats.uniqueIPs.add(userData.ipAddress);
      
      if (userData.deviceFingerprint) {
        deviceStats.uniqueDevices.add(userData.deviceFingerprint.hash);
        
        // Track devices per IP
        if (!deviceStats.devicesPerIP[userData.ipAddress]) {
          deviceStats.devicesPerIP[userData.ipAddress] = new Set();
        }
        deviceStats.devicesPerIP[userData.ipAddress].add(userData.deviceFingerprint.hash);
      }
    });

    res.json({
      totalUsers: deviceStats.totalUsers,
      uniqueIPs: Array.from(deviceStats.uniqueIPs),
      uniqueDevices: Array.from(deviceStats.uniqueDevices),
      devicesPerIP: Object.keys(deviceStats.devicesPerIP).reduce((acc, ip) => {
        acc[ip] = Array.from(deviceStats.devicesPerIP[ip]);
        return acc;
      }, {})
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get device analytics' });
  }
});

// Debug endpoint to check current IP and fingerprint
app.get('/api/debug/device-info', (req, res) => {
  const fingerprint = generateDeviceFingerprint(req);
  res.json({
    clientIp: req.clientIp,
    deviceFingerprint: fingerprint,
    headers: {
      'user-agent': req.headers['user-agent'],
      'accept': req.headers['accept'],
      'accept-language': req.headers['accept-language'],
      'sec-ch-ua': req.headers['sec-ch-ua'],
      'sec-ch-ua-platform': req.headers['sec-ch-ua-platform']
    }
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));