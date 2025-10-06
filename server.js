const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Initialize Firebase Admin
const serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// Rate limiting
const voteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'Too many voting attempts from this IP, please try again later.'
});

const signInLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many sign-in attempts from this IP, please try again later.'
});

// Middleware
app.use(cors());
app.use(express.json());

// IP address tracking
app.use((req, res, next) => {
  let clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  
  if (clientIp && clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7);
  }
  
  req.clientIp = clientIp;
  next();
});

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

// Sign In endpoint
app.post('/api/sign-in', signInLimiter, async (req, res) => {
  const { institutionalEmail, personalEmail, matricNumber, fullName } = req.body;
  
  if (!institutionalEmail || !matricNumber || !fullName) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const institutionalEmailRegex = /^(22|23|24)03(cyb|sen|ins|cmp)\d{3}@alhikmah\.edu\.ng$/i;
  if (!institutionalEmailRegex.test(institutionalEmail.toLowerCase())) {
    return res.status(400).json({ 
      error: 'Invalid institutional email format. Must be: 2203sen001@alhikmah.edu.ng' 
    });
  }

  if (personalEmail) {
    const personalEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!personalEmailRegex.test(personalEmail.toLowerCase())) {
      return res.status(400).json({ error: 'Invalid personal email format' });
    }
  }

  const emailParts = institutionalEmail.toLowerCase().split('@')[0];
  const year = emailParts.substring(0, 2);
  const department = emailParts.substring(4, 7);

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
  const normalizedPersonalEmail = personalEmail ? personalEmail.toLowerCase() : null;
  const normalizedMatric = matricNumber.toLowerCase();
  const normalizedName = fullName.trim();

  try {
    const userDocs = await db.collection('Users')
      .where('institutionalEmail', '==', normalizedInstitutionalEmail)
      .get();

    let userData;
    let userId;
    let sessionToken = generateSessionToken();

    if (!userDocs.empty) {
      userId = userDocs.docs[0].id;
      userData = userDocs.docs[0].data();
      
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
        lastIp: req.clientIp,
        sessionToken: sessionToken,
        sessionExpiry: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 2 * 60 * 60 * 1000))
      };

      if (normalizedPersonalEmail) {
        updateData.personalEmail = normalizedPersonalEmail;
      }

      await db.collection('Users').doc(userId).update(updateData);

      const remainingPositions = allPositions.filter(pos => 
        !userData.votedPositions?.includes(pos)
      );
      
      return res.status(200).json({ 
        message: 'Sign-in successful', 
        institutionalEmail: normalizedInstitutionalEmail,
        personalEmail: normalizedPersonalEmail || userData.personalEmail,
        matricNumber: normalizedMatric,
        fullName: userData.fullName,
        remainingPositions,
        sessionToken,
        continueVoting: true
      });
    }

    const newUserRef = db.collection('Users').doc();
    userId = newUserRef.id;

    userData = {
      institutionalEmail: normalizedInstitutionalEmail,
      personalEmail: normalizedPersonalEmail,
      matricNumber: normalizedMatric,
      fullName: normalizedName,
      votedPositions: [],
      ipAddress: req.clientIp,
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
    res.status(500).json({ error: 'Sign-in failed' });
  }
});

// Vote endpoint
app.post('/api/vote', voteLimiter, verifySession, async (req, res) => {
  const { institutionalEmail, candidateId, position } = req.body;
  const ipAddress = req.clientIp;

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

      const recentVotes = await transaction.get(
        db.collection('Votes')
          .where('ipAddress', '==', ipAddress)
          .where('timestamp', '>', admin.firestore.Timestamp.fromDate(new Date(Date.now() - 3600000)))
      );

      if (recentVotes.size > 2) {
        throw new Error('Too many votes from this IP address recently');
      }

      const voteRef = db.collection('Votes').doc();
      transaction.set(voteRef, {
        candidateId,
        userId: req.userId,
        userInstitutionalEmail: normalizedInstitutionalEmail,
        position,
        ipAddress,
        timestamp: admin.firestore.Timestamp.now(),
        userAgent: req.headers['user-agent']
      });

      transaction.update(userRef, {
        votedPositions: admin.firestore.FieldValue.arrayUnion(position),
        lastVoteTimestamp: admin.firestore.Timestamp.now(),
        lastVoteIp: ipAddress,
        totalVotes: (userData.totalVotes || 0) + 1
      });
    });

    res.status(200).json({ 
      message: 'Vote submitted successfully',
      position: position
    });

  } catch (error) {
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
    const votes = await db.collection('Votes').get();
    const candidates = await db.collection('Candidates').get();
    
    const voteList = votes.docs.map(doc => {
      const voteData = doc.data();
      const candidate = candidates.docs.find(c => c.id === voteData.candidateId);
      
      return {
        id: doc.id,
        position: voteData.position,
        candidateName: candidate ? candidate.data().name : 'Unknown',
        timestamp: voteData.timestamp,
      };
    });
    
    voteList.sort((a, b) => {
      const timeA = a.timestamp?.toDate?.() || new Date(a.timestamp);
      const timeB = b.timestamp?.toDate?.() || new Date(b.timestamp);
      return timeB - timeA;
    });
    
    res.status(200).json({
      votes: voteList,
      totalVotes: voteList.length,
      lastUpdated: new Date().toISOString()
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch votes table' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));