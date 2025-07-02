require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 8080;

// Decode credentials and token from BASE64 vars
function decodeEnvFile(varName, filePath) {
  const base64 = process.env[varName];
  if (!base64) throw new Error(`${varName} not set`);
  const decoded = Buffer.from(base64, 'base64').toString('utf8');
  fs.writeFileSync(filePath, decoded);
}

decodeEnvFile('CREDENTIALS_BASE64', 'credentials.json');
decodeEnvFile('TOKEN_BASE64', 'token.json');

const CREDENTIALS = JSON.parse(fs.readFileSync('credentials.json'));
const TOKEN = JSON.parse(fs.readFileSync('token.json'));

// Set up OAuth2 client
const { client_secret, client_id, redirect_uris } = CREDENTIALS.installed;
const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);
oAuth2Client.setCredentials(TOKEN);

// Set up middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

// Simple auth
const USERNAME = process.env.USERNAME;
const PASSWORD_HASH = bcrypt.hashSync(process.env.PASSWORD, 10);

// Store session in memory
let loggedIn = false;

app.get('/', (req, res) => {
  if (!loggedIn) return res.redirect('/login');
  res.redirect('/dashboard');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === USERNAME && bcrypt.compareSync(password, PASSWORD_HASH)) {
    loggedIn = true;
    return res.redirect('/dashboard');
  }
  res.render('login', { error: 'Invalid credentials' });
});

app.get('/dashboard', async (req, res) => {
  if (!loggedIn) return res.redirect('/login');

  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  const { data } = await gmail.users.messages.list({
    userId: 'me',
    q: 'from:(drn@domain.com)', // customize query
    maxResults: 10,
  });

  const emails = [];

  for (const msg of data.messages || []) {
    const { data: msgData } = await gmail.users.messages.get({
      userId: 'me',
      id: msg.id,
    });

    const subjectHeader = msgData.payload.headers.find(h => h.name === 'Subject');
    const subject = subjectHeader ? subjectHeader.value : '(No Subject)';
    const snippet = msgData.snippet || '';

    emails.push({
      id: msg.id,
      subject,
      snippet,
    });
  }

  res.render('index', { emails });
});

app.listen(PORT, () => {
  console.log(`🚀 Hit Auto Track running on port ${PORT}`);
});
