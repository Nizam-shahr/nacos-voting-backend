require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

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

// IP address tracking
app.use((req, res, next) => {
  let clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;
  
  if (clientIp && clientIp.includes(',')) {
    clientIp = clientIp.split(',')[0].trim();
  }
  
  if (clientIp && clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7);
  }

  req.clientIp = clientIp;
  console.log('Client IP:', clientIp);
  next();
});

// Generate session token
const generateSessionToken = () => {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
};

// Check for duplicate personal email
const checkDuplicatePersonalEmail = async (personalEmail) => {
  try {
    const users = await db.collection('Users').get();
    let duplicateFound = false;
    let duplicateEmail = '';

    users.docs.forEach(doc => {
      const userData = doc.data();
      if (userData.personalEmail && userData.personalEmail.toLowerCase() === personalEmail.toLowerCase()) {
        duplicateFound = true;
        duplicateEmail = userData.institutionalEmail;
      }
    });

    return { duplicateFound, duplicateEmail };
  } catch (error) {
    return { duplicateFound: false, duplicateEmail: '' };
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

// Sign In - No IP checking
app.post('/api/sign-in', async (req, res) => {
  const { institutionalEmail, personalEmail, matricNumber, fullName } = req.body;
  
  if (!institutionalEmail || !matricNumber || !fullName || !personalEmail) {
    return res.status(400).json({ error: 'All fields are required' });
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

  // Validate full name
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

    // Check for duplicate personal email
    const { duplicateFound, duplicateEmail } = await checkDuplicatePersonalEmail(normalizedPersonalEmail);
    
    if (duplicateFound) {
      return res.status(400).json({ 
        error: "This personal email has already been used by another student.",
        emailBlocked: true 
      });
    }

    // Check for existing user
    const userDocs = await db.collection('Users')
      .where('institutionalEmail', '==', normalizedInstitutionalEmail)
      .get();

    let userData;
    let userId;
    let sessionToken = generateSessionToken();

    if (!userDocs.empty) {
      // Existing user
      userId = userDocs.docs[0].id;
      userData = userDocs.docs[0].data();
      
      const positions = await db.collection('Candidates').get();
      const allPositions = [...new Set(positions.docs.map(doc => doc.data().position))];
      
      if (userData.votedPositions && userData.votedPositions.length >= allPositions.length && userData.ipAddress) {
        return res.status(400).json({ 
          error: 'You have already completed voting for all positions',
          alreadyVoted: true 
        });
      }
      
      const updateData = {
        lastSignIn: admin.firestore.Timestamp.now(),
        lastIp: req.clientIp,
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

    // New user
    const newUserRef = db.collection('Users').doc();
    userId = newUserRef.id;

    userData = {
      institutionalEmail: normalizedInstitutionalEmail,
      personalEmail: normalizedPersonalEmail,
      matricNumber: normalizedMatric,
      fullName: normalizedName,
      votedPositions: [],
      candidateIds: [],
      ipAddress: null,
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

// Vote endpoint - Store in Users, no IP checking
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

      // Update user with vote
      transaction.update(userRef, {
        votedPositions: admin.firestore.FieldValue.arrayUnion(position),
        candidateIds: admin.firestore.FieldValue.arrayUnion({ position, candidateId }),
        lastVoteTimestamp: admin.firestore.Timestamp.now(),
        lastVoteIp: req.clientIp,
        totalVotes: admin.firestore.FieldValue.increment(1)
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

// Complete Voting endpoint - Check and store IP when all positions are done
app.post('/api/complete-voting', verifySession, async (req, res) => {
  const { institutionalEmail } = req.body;

  try {
    const userDoc = await db.collection('Users').doc(req.userId).get();
    if (!userDoc.exists) {
      return res.status(400).json({ error: 'User not found' });
    }

    const userData = userDoc.data();
    const positions = await db.collection('Candidates').get();
    const allPositions = [...new Set(positions.docs.map(doc => doc.data().position))];

    // Check if user has voted for all positions
    if (!userData.votedPositions || userData.votedPositions.length < allPositions.length) {
      return res.status(400).json({ error: 'You have not completed voting for all positions' });
    }

    // Check if IP has already completed voting
    const ipDocs = await db.collection('Users')
      .where('ipAddress', '==', req.clientIp)
      .where('ipAddress', '!=', null)
      .get();

    if (!ipDocs.empty) {
      // Invalidate user's votes
      await db.collection('Users').doc(req.userId).update({
        candidateIds: [],
        votedPositions: [],
        totalVotes: 0,
        ipAddress: null,
        voteTimestamp: null
      });

      return res.status(400).json({ 
        error: 'This IP address has already been used to complete voting. Your votes have been invalidated.',
        duplicateIP: true
      });
    }

    // Update user with IP address and vote timestamp
    await db.collection('Users').doc(req.userId).update({
      ipAddress: req.clientIp,
      voteTimestamp: admin.firestore.Timestamp.now()
    });

    res.status(200).json({ 
      message: 'Voting completed successfully! Thank you for voting.',
      completed: true
    });

  } catch (error) {
    console.error('Complete voting error:', error);
    res.status(500).json({ error: 'Failed to complete voting' });
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
    const users = await db.collection('Users').where('ipAddress', '!=', null).get();
    
    const voteCounts = {};
    let totalValidVotes = 0;
    
    // Initialize positions with candidates
    candidates.docs.forEach(candidateDoc => {
      const { name, position } = candidateDoc.data();
      if (!voteCounts[position]) voteCounts[position] = [];
      voteCounts[position].push({ name, votes: 0 });
    });
    
    // Count votes from Users collection (only valid votes with ipAddress)
    users.docs.forEach(user => {
      const userData = user.data();
      if (userData.candidateIds && userData.ipAddress) {
        userData.candidateIds.forEach(vote => {
          const { position, candidateId } = vote;
          const candidateDoc = candidates.docs.find(c => c.id === candidateId);
          if (candidateDoc && candidateDoc.data().position === position) {
            const { name } = candidateDoc.data();
            const candidateInPosition = voteCounts[position].find(c => c.name === name);
            if (candidateInPosition) {
              candidateInPosition.votes += 1;
              totalValidVotes++;
            }
          }
        });
      }
    });
    
    // Sort by votes descending
    Object.keys(voteCounts).forEach(position => {
      voteCounts[position].sort((a, b) => b.votes - a.votes);
    });
    
    res.status(200).json({
      voteCounts,
      totalValidVotes,
      totalVotes: totalValidVotes,
      lastUpdated: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error fetching vote results:', error);
    res.status(500).json({ error: 'Failed to fetch vote results' });
  }
});

// Development votes table
app.get('/api/dev/votes-table', async (req, res) => {
  try {
    const users = await db.collection('Users').get();
    const candidates = await db.collection('Candidates').get();
    
    const voteList = [];
    
    users.docs.forEach(user => {
      const userData = user.data();
      if (userData.candidateIds) {
        userData.candidateIds.forEach(vote => {
          const candidateDoc = candidates.docs.find(c => c.id === vote.candidateId);
          let formattedTimestamp = 'N/A';
          if (userData.voteTimestamp) {
            formattedTimestamp = userData.voteTimestamp.toDate
              ? userData.voteTimestamp.toDate().toLocaleString()
              : new Date(userData.voteTimestamp._seconds * 1000).toLocaleString();
          }
          
          voteList.push({
            id: `${user.id}-${vote.position}`,
            userInstitutionalEmail: userData.institutionalEmail,
            position: vote.position,
            candidateName: candidateDoc ? candidateDoc.data().name : 'Unknown Candidate',
            timestamp: formattedTimestamp,
            ipAddress: userData.ipAddress || 'Not completed',
            isValid: userData.ipAddress !== null
          });
        });
      }
    });
    
    // Sort by timestamp descending
    voteList.sort((a, b) => {
      const timeA = new Date(a.timestamp);
      const timeB = new Date(b.timestamp);
      return timeB - timeA;
    });
    
    res.status(200).json({
      votes: voteList,
      totalVotes: voteList.length,
      validVotes: voteList.filter(v => v.isValid).length,
      invalidVotes: voteList.filter(v => !v.isValid).length,
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