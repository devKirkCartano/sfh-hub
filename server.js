const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const QRCode = require('qrcode');
const mysql = require('mysql2/promise'); // Make sure to install this library using npm or yarn
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const passwordValidator = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;

// Middleware setup
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('./public'));
app.set('view engine', 'ejs');
const sessionSecret = process.env.SESSION_SECRET || 'your-default-session-secret';
app.use(session({ secret: sessionSecret, resave: true, saveUninitialized: true }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(cors());

// Database connection setup
const userPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

async function connectToUserDatabase() {
  try {
    const connection = await userPool.getConnection();
    return connection;
  } catch (error) {
    console.error('Error connecting to the user database:', error.message);
    if (connection) {
      connection.release();
    }
    throw error;
  }
}

// Passport configuration for user side
passport.use('user', new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    let connectionUserPassport;
    try {
      connectionUserPassport = await userPool.getConnection();
      const [rows] = await connectionUserPassport.execute('SELECT * FROM users WHERE email = ?', [email]);
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: 'Invalid email or password' });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return done(null, false, { message: 'Invalid email or password' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    } finally{
      if(connectionUserPassport){
        connectionUserPassport.release();
      }
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  let connectionUserDeserialize;

  try {
    connectionUserDeserialize = await userPool.getConnection();
    const [rows] = await connectionUserDeserialize.execute('SELECT * FROM users WHERE id = ?', [id]);
    const user = rows[0];

    if (!user) {
      return done(new Error('User not found'));
    }
    
    done(null, user);
  } catch (error) {
    done(error, null);
  } finally {
    if (connectionUserDeserialize) {
      connectionUserDeserialize.release();
    }
  }
});


function checkAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    return next();
  }
  res.redirect('/home');
};

function checkNotAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    return res.redirect('/');
  }
  next();
};

function preventCaching(req, res, next) {
  res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.header('Expires', '-1');
  res.header('Pragma', 'no-cache');
  next();
}

// Routes

// Home page route
app.get('/', checkAuthenticated, preventCaching, async (req, res) => {
  try {
    // Assuming the user is logged in, retrieve the user from the database
    const user = req.user;

    if (!user) {
      // Redirect to the login page if the user is not logged in
      return res.redirect('/home');
    }

    // Render the main page that includes the user's QR code
    res.render("index.ejs", { user, qrCodePath: user.qrCodePath });
  } catch (error) {
    console.error('Error retrieving user:', error.message);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/profile', checkAuthenticated, preventCaching, (req, res) => {
  res.render("profile.ejs", { error: req.flash('error'), success: req.flash('success') });
});

app.get('/billing', checkAuthenticated, preventCaching, (req, res) => {
  res.render("billing.ejs", { error: req.flash('error'), success: req.flash('success') });
});

// Login page route
app.get('/login', checkNotAuthenticated, preventCaching, (req, res) => {
  res.render("login.ejs", { message: req.flash('error') });
});

// Register page route
app.get('/register', checkNotAuthenticated , preventCaching, (req, res) => {
  res.render("register.ejs", { error: req.flash('error'), success: req.flash('success') });
});

app.get('/home', checkNotAuthenticated , preventCaching, (req, res) => {
  res.render("front-index.ejs", { error: req.flash('error'), success: req.flash('success') });
});

app.get('/about', checkNotAuthenticated , preventCaching, (req, res) => {
  res.render("about.ejs", { error: req.flash('error'), success: req.flash('success') });
});

app.get('/facility', checkNotAuthenticated , preventCaching, (req, res) => {
  res.render("facility.ejs", { error: req.flash('error'), success: req.flash('success') });
});

app.get('/plan', checkNotAuthenticated , preventCaching, (req, res) => {
  res.render("plan.ejs", { error: req.flash('error'), success: req.flash('success') });
});

app.get('/faqs', checkNotAuthenticated , preventCaching, (req, res) => {
  res.render("faqs.ejs", { error: req.flash('error'), success: req.flash('success') });
});

app.get('/contact', checkNotAuthenticated , preventCaching, (req, res) => {
  res.render("contact.ejs", { error: req.flash('error'), success: req.flash('success') });
});

// Login endpoint
app.post('/login', checkNotAuthenticated, passport.authenticate('user', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true,
}));

// Registration endpoint
app.post('/register', checkNotAuthenticated, preventCaching, async (req, res) => {
  let connectionUserRegister;

  try {
    const { firstName, lastName, email, password, re_pass, membershipType } = req.body;

    if (password !== re_pass) {
      req.flash('error', 'Password and confirmation do not match');
      return res.redirect('/register');
    }

    if (!passwordValidator.test(password)) {
      req.flash('error', 'Password must have a minimum of 8 characters, at least one capital letter, one number, and one special character');
      return res.redirect('/register');
    }

    connectionUserRegister = await userPool.getConnection();

    const [existingUserRows] = await connectionUserRegister.execute('SELECT * FROM users WHERE email = ?', [email]);
    const existingUser = existingUserRows[0];
    
    if (existingUser) {
      req.flash('error', 'User with this email already exists');
      return res.redirect('/register');
    }

    // Generate QR code for the user
    const userIdentifier = `${encodeURIComponent(firstName + lastName)}`.replace(/%20/g, '-');
    const qrData = JSON.stringify({
      "UserID": userIdentifier,
      "firstName": `${firstName}`,
      "lastName": `${lastName}`,
      "Email": email,
    });

    // Full path for creating QR code
    const qrCodeFullPath = `./public/qrcodes/${userIdentifier}.png`;
    await QRCode.toFile(qrCodeFullPath, qrData);

    // Path for referencing in index.ejs
    const qrCodePathForIndex = `/qrcodes/${userIdentifier}.png`;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the user in the database
    const [result] = await connectionUserRegister.execute('INSERT INTO users (firstName, lastName, email, password, qrCodePath, membershipType) VALUES (?, ?, ?, ?, ?, ?)', [firstName, lastName, email, hashedPassword, qrCodePathForIndex, membershipType]);

    // Assuming you want to display a success message
    req.flash('success', 'User registered successfully');

    // Link subscriptions to the user based on the email
    await connectionUserRegister.execute('UPDATE subscribed_members SET userId = ? WHERE email = ? AND userId IS NULL', [result.insertId, email]);

    return res.redirect('/register');
  } catch (error) {
    console.error('Error registering user:', error.message);

    // Assuming you want to display an error message for internal server errors
    req.flash('error', 'Internal Server Error');

    res.status(500).send('Internal Server Error');
  } finally {
    if (connectionUserRegister) {
      connectionUserRegister.release();
    }
  }
});



app.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Error during logout:', err.message);
    }
    res.redirect('/login');
  });
});

app.get('/get_announcements', async (req, res) => {
  let connectionGetAnnouncements;
  try {
      connectionGetAnnouncements = await userPool.getConnection();
      const [announcements] = await connectionGetAnnouncements.query('SELECT * FROM announcements');
      res.json(announcements);
  } catch (error) {
      console.error('Error fetching announcements:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
  } finally {
      if (connectionGetAnnouncements) {
        connectionGetAnnouncements.release();
      }
  }
});

// Add this route to your server code
app.get('/getUserDetails', checkAuthenticated, (req, res) => {
  try {
    // Assuming the user is logged in, retrieve the user from the database
    const user = req.user;

    if (!user) {
      // If the user is not found, return an error status
      return res.status(404).json({ error: 'User not found' });
    }

    // Send the user details in JSON format
    res.json({
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      membershipType: user.membershipType,
      contactNumber: user.contactNumber,
    });
  } catch (error) {
    console.error('Error retrieving user details:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Helper function to fetch billing history
async function getBillingHistory(userId) {
  let connectionBillingHistory;

  try {
    connectionBillingHistory = await userPool.getConnection();

    const [billingRows] = await connectionBillingHistory.execute(`
      SELECT b.bill_id, b.userId, b.membershipType, b.amount, b.date_paid, b.subscription_expiration
      FROM subscribed_members sm
      JOIN bills b ON sm.subscribedId = b.userId
      WHERE sm.userId = ?
    `, [userId]);

    return billingRows;
  } catch (error) {
    console.error('Error fetching billing history:', error.message);
    throw error;
  } finally {
    if (connectionBillingHistory) {
      connectionBillingHistory.release();
    }
  }
}

// Billing history route
app.get('/getBillingHistory', checkAuthenticated, async (req, res) => {
  try {
    // Assuming the user is logged in, retrieve the user from the database
    const user = req.user;

    if (!user) {
      // If the user is not found, return an error status
      return res.status(404).json({ error: 'User not found' });
    }

    // Get billing history for the user
    const billingHistory = await getBillingHistory(user.id);

    // Send the billing history in JSON format
    res.json(billingHistory);
  } catch (error) {
    console.error('Error retrieving billing history:', error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/updateUser', checkAuthenticated, async (req, res) => {
  let connectionUpdateUser;

  try {
    const { firstName, lastName, contactNumber } = req.body;

    // Assuming the user is logged in, retrieve the user from the database
    const user = req.user;

    if (!user) {
      // If the user is not found, return an error status
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user data
    connectionUpdateUser = await userPool.getConnection();
    await connectionUpdateUser.execute('UPDATE users SET firstName = ?, lastName = ?, contactNumber = ? WHERE id = ?', [firstName, lastName, contactNumber, user.id]);

    // Update user data in subscribed_members
    await connectionUpdateUser.execute('UPDATE subscribed_members SET firstName = ?, lastName = ?, contactNumber = ? WHERE userId = ?', [firstName, lastName, contactNumber, user.id]);

    // Assuming you want to display a success message
    req.flash('success', 'User information updated successfully');

    // Send the updated user details in JSON format
    res.json({
      firstName: firstName,
      lastName: lastName,
      contactNumber: contactNumber,
    });
  } catch (error) {
    console.error('Error updating user information:', error.message);

    // Assuming you want to display an error message for internal server errors
    req.flash('error', 'Internal Server Error');

    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    if (connectionUpdateUser) {
      connectionUpdateUser.release();
    }
  }
});

// Update password endpoint
app.post('/updatePassword', checkAuthenticated, async (req, res) => {
  let connectionUpdatePassword;

  try {
    const { currentPassword, newPassword } = req.body;

    // Assuming the user is logged in, retrieve the user from the database
    const user = req.user;

    if (!user) {
      // If the user is not found, return an error status
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if the current password is correct
    const passwordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash the new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password
    connectionUpdatePassword = await userPool.getConnection();
    await connectionUpdatePassword.execute('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, user.id]);

    // Assuming you want to display a success message
    req.flash('success', 'Password updated successfully');

    // Send the updated user details in JSON format
    res.json({
      success: true,
      message: 'Password updated successfully',
    });
  } catch (error) {
    console.error('Error updating password:', error.message);

    // Assuming you want to display an error message for internal server errors
    req.flash('error', 'Internal Server Error');

    res.status(500).json({ error: 'Internal Server Error' });
  } finally {
    if (connectionUpdatePassword) {
      connectionUpdatePassword.release();
    }
  }
});


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});