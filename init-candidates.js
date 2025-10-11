const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'voting.db'));

const candidates = [
  { id: 'candidate111', name: 'Alowonle Olayinka Abdulrazzak', position: 'President' },
  { id: 'candidate112', name: 'Fadlullah Folajomi Babalola', position: 'President' },
  { id: 'candidate113', name: 'Buhari Muhammad Maaji', position: 'President' },
  { id: 'candidate211', name: 'Sadiq Fareedah Adedoyin', position: 'Vice President' },
  { id: 'candidate212', name: 'Abubakar Fatihu Olanrewaju', position: 'Vice President' },
  { id: 'candidate311', name: 'Sulayman Umar Toyin', position: 'Senate President' },
  { id: 'candidate312', name: 'Isah Ahmad', position: 'Senate President' },
  { id: 'candidate411', name: 'Surajo Umar Sadiq', position: 'Treasurer' },
  { id: 'candidate412', name: 'Abubakar Faruku Saad', position: 'Treasurer' }
];

db.exec('BEGIN');
const insertCandidate = db.prepare('INSERT OR IGNORE INTO Candidates (id, name, position) VALUES (?, ?, ?)');
candidates.forEach(candidate => {
  insertCandidate.run(candidate.id, candidate.name, candidate.position);
});
db.exec('COMMIT');
db.close();
console.log('Candidates initialized');