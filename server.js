const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
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
  let clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  // Handle multiple IPs in x-forwarded-for (common with proxies)
  if (clientIp && clientIp.includes(',')) {
    // Take the first IP which is the original client IP
    clientIp = clientIp.split(',')[0].trim();
  }
  
  // Remove IPv6 prefix if present
  if (clientIp && clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7);
  }
  
  req.clientIp = clientIp;
  console.log('Extracted client IP:', clientIp); // For debugging
  next();
});

// Generate session token
const generateSessionToken = () => {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
};

// Improved IP checking - Only check the actual client IP
const checkIPSignedIn = async (ipAddress) => {
  try {
    console.log('Checking IP in database:', ipAddress);
    
    const users = await db.collection('Users').get();
    let ipFound = false;
    
    // Check all users for this IP
    users.docs.forEach(doc => {
      const userData = doc.data();
      const storedIp = userData.ipAddress;
      
      // Handle both single IP and comma-separated IPs
      if (storedIp) {
        if (storedIp.includes(',')) {
          // If stored as multiple IPs, check each one
          const ipList = storedIp.split(',').map(ip => ip.trim());
          if (ipList.includes(ipAddress)) {
            ipFound = true;
            console.log('IP found in existing user:', userData.institutionalEmail);
          }
        } else if (storedIp === ipAddress) {
          ipFound = true;
          console.log('IP found in existing user:', userData.institutionalEmail);
        }
      }
    });
    
    return ipFound;
  } catch (error) {
    console.error('Error checking IP sign-ins:', error);
    return false;
  }
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

// Enhanced Sign In with STRICT IP restriction
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
    // STRICT IP CHECKING - Check if IP has already signed in
    const ipHasSignedIn = await checkIPSignedIn(req.clientIp);
    if (ipHasSignedIn) {
      console.log('IP BLOCKED - Already used:', req.clientIp);
      return res.status(400).json({ 
        error: 'This device/network has already been used for voting. Each device/network can only be used once for the entire election period. Please use a different device or network.',
        ipBlocked: true 
      });
    }

    const userDocs = await db.collection('Users')
      .where('institutionalEmail', '==', normalizedInstitutionalEmail)
      .get();

    let userData;
    let userId;
    let sessionToken = generateSessionToken();

    if (!userDocs.empty) {
      userId = userDocs.docs[0].id;
      userData = userDocs.docs[0].data();
      
      // Check if this existing user's IP matches current IP
      const existingUserIp = userData.ipAddress;
      if (existingUserIp && existingUserIp.includes(req.clientIp)) {
        console.log('User exists with same IP - allowing continuation');
      } else {
        // User exists but with different IP - BLOCK
        console.log('User exists with different IP - BLOCKING:', existingUserIp, 'vs', req.clientIp);
        return res.status(400).json({ 
          error: 'This student account has already been used from a different device/network. Each student can only vote once.',
          ipBlocked: true 
        });
      }
      
      const positions = await db.collection('Candidates').get();
      const allPositions = [...new Set(positions.docs.map(doc => doc.data().position))];
      
      if (userData.votedPositions && userData.votedPositions.length >= allPositions.length) {
        return res.status(400).json({ 
          error: 'You have already completed voting for all positions',
          alreadyVoted: true 
        });
      }
      
      const updateData = {
        lastSignIn: admin.firestore.Timestamp.now(),
        lastIp: req.clientIp, // Store only the client IP
        sessionToken: sessionToken,
        sessionExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 2 * 60 * 60 * 1000)),
        personalEmail: normalizedPersonalEmail,
        fullName: normalizedName
      };

      await db.collection('Users').doc(userId).update(updateData);

      const remainingPositions = allPositions.filter(pos => 
        !userData.votedPositions?.includes(pos)
      );
      
      return res.status(200).json({ 
        message: 'Sign-in successful', 
        institutionalEmail: normalizedInstitutionalEmail,
        personalEmail: normalizedPersonalEmail,
        matricNumber: normalizedMatric,
        fullName: normalizedName,
        remainingPositions,
        sessionToken,
        continueVoting: true
      });
    }

    // NEW USER - Create with strict IP tracking
    const newUserRef = db.collection('Users').doc();
    userId = newUserRef.id;

    userData = {
      institutionalEmail: normalizedInstitutionalEmail,
      personalEmail: normalizedPersonalEmail,
      matricNumber: normalizedMatric,
      fullName: normalizedName,
      votedPositions: [],
      ipAddress: req.clientIp, // Store ONLY the client IP
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

// Vote endpoint - Also check IP during voting
app.post('/api/vote', verifySession, async (req, res) => {
  const { institutionalEmail, candidateId, position } = req.body;

  if (!candidateId || !position) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const normalizedInstitutionalEmail = institutionalEmail.toLowerCase();

  try {
    // Additional IP check during voting
    const ipHasSignedIn = await checkIPSignedIn(req.clientIp);
    if (ipHasSignedIn) {
      // Check if this IP belongs to the current user
      const userDocs = await db.collection('Users')
        .where('institutionalEmail', '==', normalizedInstitutionalEmail)
        .get();
      
      if (!userDocs.empty) {
        const userData = userDocs.docs[0].data();
        const userIp = userData.ipAddress;
        
        if (!userIp || !userIp.includes(req.clientIp)) {
          return res.status(400).json({ 
            error: 'Security violation: IP address mismatch. Please sign in again.',
            ipBlocked: true 
          });
        }
      }
    }

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
        ipAddress: req.clientIp, // Store only client IP
        timestamp: admin.firestore.Timestamp.now(),
        userAgent: req.headers['user-agent']
      });

      transaction.update(userRef, {
        votedPositions: admin.firestore.FieldValue.arrayUnion(position),
        lastVoteTimestamp: admin.firestore.Timestamp.now(),
        lastVoteIp: req.clientIp, // Store only client IP
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
        firebaseTimestamp: timestampValue // Keep original for reference
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