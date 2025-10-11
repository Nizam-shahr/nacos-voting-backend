const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const db = new Database(path.join(__dirname, 'voting.db'));

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());

const SALT_ROUNDS = 10;
const VOTING_POSITIONS = ['President', 'Vice President', 'Senate President', 'Treasurer'];

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS Users (
    id TEXT PRIMARY KEY,
    institutionalEmail TEXT UNIQUE,
    personalEmail TEXT,
    matricNumber TEXT,
    fullName TEXT,
    deviceId TEXT,
    signInTimestamp INTEGER,
    createdAt INTEGER,
    status TEXT,
    votedPositions TEXT DEFAULT '[]',
    candidateIds TEXT DEFAULT '[]',
    totalVotes INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS Candidates (
    id TEXT PRIMARY KEY,
    name TEXT,
    position TEXT
  );

  CREATE TABLE IF NOT EXISTS Votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId TEXT,
    userInstitutionalEmail TEXT,
    candidateId TEXT,
    candidateName TEXT,
    position TEXT,
    timestamp INTEGER,
    isValid INTEGER DEFAULT 1,
    FOREIGN KEY (userId) REFERENCES Users(id),
    FOREIGN KEY (candidateId) REFERENCES Candidates(id)
  );
`);

// Middleware to verify user
const verifyUser = (req, res, next) => {
  const { institutionalEmail, deviceId } = req.body;
  if (!institutionalEmail || !deviceId) {
    console.error('Missing fields:', { institutionalEmail, deviceId });
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const user = db.prepare(`
    SELECT id, institutionalEmail, deviceId
    FROM Users
    WHERE institutionalEmail = ? AND deviceId = ?
  `).get(institutionalEmail, deviceId);

  if (!user) {
    console.error('User or device not found:', { institutionalEmail, deviceId });
    return res.status(401).json({ error: 'Invalid user or device ID' });
  }

  req.user = user;
  next();
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Sign-in endpoint
app.post('/api/sign-in', async (req, res) => {
  const { institutionalEmail, personalEmail, matricNumber, fullName, deviceId } = req.body;

  if (!institutionalEmail || !personalEmail || !matricNumber || !fullName || !deviceId) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (!institutionalEmail.endsWith('@alhikmah.edu.ng')) {
    return res.status(400).json({ error: 'Invalid institutional email' });
  }

  try {
    const existingDevice = db.prepare('SELECT institutionalEmail FROM Users WHERE deviceId = ?').get(deviceId);
    if (existingDevice && existingDevice.institutionalEmail !== institutionalEmail) {
      console.error('Device ID already used by another user:', { deviceId, existingEmail: existingDevice.institutionalEmail });
      return res.status(400).json({ error: 'You have already voted.', deviceBlocked: true });
    }

    const existingUser = db.prepare('SELECT * FROM Users WHERE institutionalEmail = ?').get(institutionalEmail);
    if (existingUser) {
      if (existingUser.status === 'completed') {
        return res.status(400).json({ error: 'You have already completed voting.', alreadyVoted: true });
      }
      if (existingUser.deviceId !== deviceId) {
        return res.status(400).json({ error: 'Device ID does not match registered device.', deviceBlocked: true });
      }
      if (existingUser.personalEmail !== personalEmail) {
        return res.status(400).json({ error: 'Personal email does not match registered email.', emailBlocked: true });
      }
      return res.status(200).json({
        message: 'Sign-in successful',
        institutionalEmail: existingUser.institutionalEmail,
        deviceId,
        remainingPositions: JSON.parse(existingUser.votedPositions).length === 0
          ? VOTING_POSITIONS
          : VOTING_POSITIONS.filter(pos => !JSON.parse(existingUser.votedPositions).includes(pos)),
        continueVoting: true
      });
    }

    const hashedEmail = await bcrypt.hash(personalEmail, SALT_ROUNDS);
    const userId = Math.random().toString(36).substring(2);
    const now = Date.now();

    db.prepare(`
      INSERT INTO Users (
        id, institutionalEmail, personalEmail, matricNumber, fullName,
        deviceId, signInTimestamp, createdAt, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      userId, institutionalEmail, hashedEmail, matricNumber, fullName,
      deviceId, now, now, 'active'
    );

    console.log(`New user created: ${institutionalEmail}, Device ID: ${deviceId}`);

    res.status(200).json({
      message: 'Sign-in successful',
      institutionalEmail,
      deviceId,
      remainingPositions: VOTING_POSITIONS,
      continueVoting: false
    });
  } catch (err) {
    console.error('Sign-in error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get positions
app.get('/api/positions', (req, res) => {
  const positions = db.prepare('SELECT DISTINCT position FROM Candidates').all().map(row => row.position);
  console.log('Positions fetched:', positions);
  res.json(positions);
});

// Get candidates for a position
app.get('/api/candidates/:position', (req, res) => {
  const { position } = req.params;
  if (!VOTING_POSITIONS.includes(position)) {
    console.error('Invalid position requested:', position);
    return res.status(400).json({ error: 'Invalid position' });
  }
  const candidates = db.prepare('SELECT * FROM Candidates WHERE position = ?').all(position);
  console.log(`Candidates fetched for ${position}:`, candidates);
  res.json(candidates);
});

// Submit vote
app.post('/api/vote', verifyUser, async (req, res) => {
  const { candidateId, position } = req.body;
  const { institutionalEmail, deviceId } = req.user;

  console.log('Vote attempt:', { institutionalEmail, candidateId, position, deviceId });

  if (!candidateId || !position) {
    console.error('Missing vote fields:', { candidateId, position });
    return res.status(400).json({ error: 'Missing candidateId or position' });
  }

  try {
    const candidate = db.prepare('SELECT * FROM Candidates WHERE id = ? AND position = ?').get(candidateId, position);
    if (!candidate) {
      console.error('Invalid candidate:', { candidateId, position });
      return res.status(400).json({ error: 'Invalid candidate or position' });
    }

    const user = db.prepare('SELECT * FROM Users WHERE institutionalEmail = ?').get(institutionalEmail);
    let votedPositions = JSON.parse(user.votedPositions);
    let candidateIds = JSON.parse(user.candidateIds);

    if (votedPositions.includes(position)) {
      console.error('Already voted for position:', { institutionalEmail, position });
      return res.status(400).json({ error: 'You have already voted for this position' });
    }

    votedPositions.push(position);
    candidateIds.push({ position, candidateId });

    const now = Date.now();
    await db.transaction(() => {
      db.prepare(`
        UPDATE Users
        SET votedPositions = ?, candidateIds = ?, totalVotes = totalVotes + 1
        WHERE institutionalEmail = ?
      `).run(JSON.stringify(votedPositions), JSON.stringify(candidateIds), institutionalEmail);

      db.prepare(`
        INSERT INTO Votes (userId, userInstitutionalEmail, candidateId, candidateName, position, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(user.id, institutionalEmail, candidateId, candidate.name, position, now);
    })();

    console.log('Vote recorded:', { institutionalEmail, candidateId, position });
    res.json({ message: 'Vote recorded successfully' });
  } catch (err) {
    console.error(`Vote error for ${institutionalEmail}:`, err);
    res.status(400).json({ error: 'Failed to record vote' });
  }
});

// Complete voting
app.post('/api/complete-voting', verifyUser, async (req, res) => {
  const { institutionalEmail } = req.user;

  try {
    db.prepare('UPDATE Users SET status = ? WHERE institutionalEmail = ?').run('completed', institutionalEmail);
    res.json({ message: 'Voting completed' });
  } catch (err) {
    console.error('Complete voting error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Public vote results
app.get('/api/public/votes', (req, res) => {
  try {
    const voteCounts = {};
    VOTING_POSITIONS.forEach(position => {
      const candidates = db.prepare(`
        SELECT c.name, COUNT(v.id) as votes
        FROM Candidates c
        LEFT JOIN Votes v ON c.id = v.candidateId AND v.position = c.position AND v.isValid = 1
        WHERE c.position = ?
        GROUP BY c.name
      `).all(position);
      voteCounts[position] = candidates;
    });

    const totalValidVotes = db.prepare('SELECT COUNT(*) as count FROM Votes WHERE isValid = 1').get().count;

    res.json({ voteCounts, totalValidVotes, lastUpdated: new Date().toISOString() });
  } catch (err) {
    console.error('Public votes error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin votes table
app.get('/api/dev/votes-table', (req, res) => {
  try {
    const votes = db.prepare(`
      SELECT v.id, v.userInstitutionalEmail, v.candidateName, v.position, v.timestamp, v.isValid
      FROM Votes v
      ORDER BY v.timestamp DESC
    `).all();

    const totalVotes = db.prepare('SELECT COUNT(*) as count FROM Votes WHERE isValid = 1').get().count;

    res.json({ votes, totalVotes, lastUpdated: new Date().toISOString() });
  } catch (err) {
    console.error('Votes table error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});