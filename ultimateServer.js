//modules
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const adminPassport = require('passport');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const QRCode = require('qrcode');
const mysql = require('mysql2/promise'); 
const cron = require('node-cron');
const moment = require('moment');
const cors = require('cors');
require('dotenv').config();

// Middleware setup
const app = express();
const PORT = process.env.PORT || 3000;
const passwordValidator = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
const usernameValidator = /^[a-zA-Z0-9_]+$/;

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('./public'));
app.set('view engine', 'ejs');
const sessionSecret = process.env.SESSION_SECRET || 'your-default-session-secret';
app.use(session({ secret: sessionSecret, resave: true, saveUninitialized: true }));
app.use(flash());
app.use('/admin', adminPassport.initialize());
app.use(passport.initialize());
app.use('/admin', adminPassport.session());
app.use(passport.session());
app.use(cors());

// Database connection setup
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  async function connectToDatabase() {
    let connection
    try {
      const connection = await pool.getConnection();
      return connection;
    } catch (error) {
      console.error('Error connecting to the database:', error.message);
      if (connection) {
        connection.release();
      }
      throw error;
    } finally {
      if (connection) {
        connection.release();
      }
    }
  }

  // Passport configuration for user side
  passport.use('user', new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
      let connectionUserPassport;
      try {
        connectionUserPassport = await pool.getConnection();
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
      connectionUserDeserialize = await pool.getConnection();
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
  
  // Passport configuration
  adminPassport.use('admin', new LocalStrategy(
    { usernameField: 'name' },
    async (username, password, done) => {
      let connectionPassport;
      try {
        connectionPassport = await pool.getConnection();
        // Use BINARY to make the comparison case-sensitive
        const [rows] = await connectionPassport.execute('SELECT * FROM adminusers WHERE BINARY name = ?', [username]);
        const user = rows[0];
  
        if (!user) {
          return done(null, false, { message: 'Invalid username or password' });
        }
  
        const passwordMatch = await bcrypt.compare(password, user.password);
  
        if (!passwordMatch) {
          return done(null, false, { message: 'Invalid username or password' });
        }
  
        return done(null, user);
      } catch (error) {
        return done(error);
      } finally {
        if (connectionPassport) {
          connectionPassport.release();
        }
      }
    }
  ));
  
  adminPassport.serializeUser((user, done) => {
    done(null, user.name);
  });
  
  adminPassport.deserializeUser(async (username, done) => {
    let connectionDeserialize;
  
    try {
      connectionDeserialize = await pool.getConnection();
      const [rows] = await connectionDeserialize.execute('SELECT * FROM adminusers WHERE name = ?', [username]);
      const user = rows[0];
  
      if (!user) {
        return done(new Error('User not found'));
      }
      
      done(null, user);
    } catch (error) {
      done(error, null);
    } finally{
      if (connectionDeserialize){
        connectionDeserialize.release();
      }
    }
  });
  
  const pathPrefix = '/admin';
  
  //Authentication for session in admin
  function checkAuthenticatedAdmin(req, res, next){
    if(req.isAuthenticated()){
      return next();
    }
    res.redirect(`${pathPrefix}/login`);
  };
  
  function checkNotAuthenticatedAdmin(req, res, next){
    if(req.isAuthenticated()){
      return res.redirect(`${pathPrefix}/`);
    }
    next();
  };

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
  // Main page route
  app.get(`${pathPrefix}/`, checkAuthenticatedAdmin, preventCaching, async (req, res) => {
    try {
      // Assuming the user is logged in, retrieve the user from the database
      const user = req.user;
      
      if (!user) {
        // Redirect to the login page if the user is not logged in
        return res.redirect(`${pathPrefix}/login`);
      }
  
      // Render the main page that includes the user's QR code
      res.render("index-admin.ejs", { user });
    } catch (error) {
      console.error('Error retrieving user:', error.message);
      res.status(500).send('Internal Server Error');
    }
  });
  
  // Login page route
  app.get(`${pathPrefix}/login`, checkNotAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("login-admin.ejs", { message: req.flash('error') });
  });
  
  // Register page route
  app.get(`${pathPrefix}/register`, checkAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("register-admin.ejs", { error: req.flash('error'), success: req.flash('success') });
  });
  
  // Announcement page route
  app.get(`${pathPrefix}/announcement-form`, checkAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("announcement-admin.ejs", { error: req.flash('error'), success: req.flash('success') });
  });
  
  // Application form page route
  app.get(`${pathPrefix}/application-form`, checkAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("applicationForm-admin.ejs", { error: req.flash('error'), success: req.flash('success') });
  });
  
  // Accounting page route
  app.get(`${pathPrefix}/accounting`, checkAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("accounting-admin.ejs", { error: req.flash('error'), success: req.flash('success') });
  });
  
  // QR scanner page route
  app.get(`${pathPrefix}/scanner-page`, checkAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("scanner-admin.ejs", { error: req.flash('error'), success: req.flash('success') });
  });
  
  // Billing page route
  app.get(`${pathPrefix}/billing`, checkAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("billing-admin.ejs", { error: req.flash('error'), success: req.flash('success') });
  });
  
  // User profile page route
  app.get(`${pathPrefix}/profile`, checkAuthenticatedAdmin, preventCaching, (req, res) => {
    res.render("userProfile-admin.ejs", { error: req.flash('error'), success: req.flash('success') });
  });
  
  // Gets the name for the admin that is currently logged in
  app.get('/admin/getLoggedInAdminName', checkAuthenticatedAdmin, async (req, res) => {
    let connectionGetLoggedInAdmin;
    try {
      // Acquire a connection from the pool
      connectionGetLoggedInAdmin = await pool.getConnection();
  
      // Assuming you have a user object in the request (req.user) with the admin's name
      const admin = req.user;
  
      // Query to fetch the admin's name from the adminusers table
      const query = `
        SELECT name
        FROM adminusers
        WHERE name = ?
      `;
  
      // Execute the query and retrieve the admin's name
      const [adminInfo] = await connectionGetLoggedInAdmin.execute(query, [admin.name]);
  
      // Send the JSON response containing the admin's name
      res.json({ name: adminInfo[0].name });
    } catch (error) {
      console.error('Error fetching logged-in admin name:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      // Release the connection back to the pool, whether an error occurred or not
      if (connectionGetLoggedInAdmin) {
        connectionGetLoggedInAdmin.release();
      }
    }
  });
  
  // Login endpoint
  app.post(`${pathPrefix}/login`, checkNotAuthenticatedAdmin, adminPassport.authenticate('admin', {
      successRedirect: `${pathPrefix}/`,
      failureRedirect: `${pathPrefix}/login`,
      failureFlash: true,
    }));
  
  // Registration endpoint
  app.post(`${pathPrefix}/register`, checkNotAuthenticatedAdmin, preventCaching, async (req, res) => {
    let connectionRegister;
  
    try {
      const { name, password, re_pass } = req.body;
  
      if (password !== re_pass) {
        req.flash('error', 'Password and confirmation do not match');
        return res.redirect(`${pathPrefix}/register`);
      }
  
      if (!passwordValidator.test(password)) {
        req.flash('error', 'Password must have a minimum of 8 characters, at least one capital letter, one number, and one special character');
        return res.redirect(`${pathPrefix}/register`);
      }
  
      // Check if the username is valid
      if (!usernameValidator.test(name)) {
        req.flash('error', 'Username can only contain letters, numbers, and underscores');
        return res.redirect(`${pathPrefix}/register`);
      }
  
      connectionRegister = await pool.getConnection();
  
      const [existingNameRows] = await connectionRegister.execute('SELECT * FROM adminusers WHERE name = ?', [name]);
      const existingName = existingNameRows[0];
  
      if (existingName){
        req.flash('error', 'Username is already taken');
        return res.redirect(`${pathPrefix}/register`);
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Save the user in the database
      const [result] = await connectionRegister.execute('INSERT INTO adminusers (name, password) VALUES (?, ?)', [name, hashedPassword]);
  
      // Assuming you want to display a success message
      req.flash('success', 'User registered successfully');
  
      return res.redirect(`${pathPrefix}/register`);
    } catch (error) {
      console.error('Error registering user:', error.message);
  
      // Assuming you want to display an error message for internal server errors
      req.flash('error', 'Internal Server Error');
  
      res.status(500).send('Internal Server Error');
    } finally {
      if (connectionRegister){
        connectionRegister.release();
      }
    }
  });
  
  app.post('/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        console.error('Error during logout:', err.message);
      }
      res.redirect(`${pathPrefix}/login`);
    });
  });
  
  
  // ---------------------------------------------- QR scanner page endpoint functionalities ----------------------------------------------
  // Gets the names of the members that have been scanned to populate the table
  app.get('/getScannedNames', async (req, res) => {
    let connectionScannedNames;
    try {
      connectionScannedNames = await pool.getConnection();
      const [selectResult] = await connectionScannedNames.execute('SELECT firstName, lastName, timestamp FROM member_names ORDER BY timestamp DESC');
      const scannedNames = selectResult.map(row => ({
        firstName: row.firstName,
        lastName: row.lastName,
        timestamp: row.timestamp,
      }));
      res.json(scannedNames);
    } catch (error) {
      console.error('Error retrieving scanned names:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionScannedNames){
        connectionScannedNames.release();
      }
    }
  });
  
  // Inserts the names in the member_names database
  app.post('/record-member-name', async (req, res) => {
    let connectionRecordName;
  
    try {
      const { firstName, lastName, email } = req.body;
  
      if (!firstName || !lastName || !email) {
        console.error('Error: firstName, lastName, or email is undefined or empty');
        res.json({ success: false });
        return;
      }
  
      connectionRecordName = await pool.getConnection();
  
      // Include the current timestamp in the INSERT statement
      const timestamp = new Date(); // Current date and time
      const [insertResult] = await connectionRecordName.execute(
        'INSERT INTO member_names (firstName, lastName, email, timestamp) VALUES (?, ?, ?, ?)',
        [firstName, lastName, email, timestamp]
      );
  
      // Retrieve all scanned names from the database
      const [selectResult] = await connectionRecordName.execute(
        'SELECT firstName, lastName, email, timestamp FROM member_names ORDER BY timestamp DESC'
      );
      const scannedNames = selectResult.map(row => ({
        firstName: row.firstName,
        lastName: row.lastName,
        email: row.email,
        timestamp: row.timestamp,
      }));
  
      if (insertResult.affectedRows > 0) {
        console.log('Scanned name recorded successfully');
        // Include the timestamp in the response
        res.json({ success: true, scannedNames, timestamp });
      } else {
        console.error('Failed to record scanned name');
        res.json({ success: false });
      }
    } catch (error) {
      console.error('Error recording scanned name:', error.message);
      res.json({ success: false });
    } finally {
      if (connectionRecordName) {
        connectionRecordName.release();
      }
    }
  });
  
  // Authenticates the scanned name if it is a member
  app.post('/authenticate', async (req, res) => {
    let connectionAuthenticate;
  
    try {
      const { firstName, lastName, email } = req.body;
  
      if (!firstName || !lastName || !email) {
        console.error('Error: firstName, lastName, or email is undefined or empty');
        res.json({ success: false });
        return;
      }
  
      connectionAuthenticate = await pool.getConnection();
  
      const query = 'SELECT * FROM subscribed_members WHERE firstName = ? AND lastName = ? AND email = ?';
      const queryParams = [firstName, lastName, email];
  
      const [rows] = await connectionAuthenticate.execute(query, queryParams);
      const user = rows[0];
  
      if (user) {
        res.json({ success: true });
      } else {
        res.json({ success: false });
      }
    } catch (error) {
      console.error('Error during authentication:', error.message);
      res.json({ success: false });
    } finally {
      if (connectionAuthenticate) {
        connectionAuthenticate.release();
      }
    }
  });
  
  /*cron.schedule('17 16 * * *', async () => {
    try {
      console.log('Cron job started.');
  
      const connectionSchedule = await pool.getConnection();
  
      // Delete records older than a day
      const yesterday = moment().subtract(1, 'days').format('YYYY-MM-DD HH:mm:ss');
      console.log('Deleting records older than', yesterday);
      // Archive deleted records in a separate database table
      await connectionSchedule.execute('INSERT INTO archived_member_names (firstName, lastName, email, timestamp) SELECT firstName, lastName, email, timestamp FROM member_names WHERE timestamp < ?', [specifiedTimestamp]);
  
      await connectionSchedule.execute('DELETE FROM member_names WHERE timestamp < ?', [yesterday]);
  
      console.log('Cron job executed: Deleted and archived scanned names.');
    } catch (error) {
      console.error('Error during cron job:', error.message);
    } finally {
      if (connectionSchedule) {
        connectionSchedule.release();
      }
    }
  });
  */
  cron.schedule('12 12 * * *', async () => {
    try {
      console.log('Cron job started.');
  
      const connectionSchedule = await pool.getConnection();
  
      // Specify the timestamp for deletion and archiving (adjust as needed)
      const specifiedTimestamp = '2023-12-17 12:04:20';
  
      // Delete records older than the specified timestamp
      console.log('Deleting records older than', specifiedTimestamp);
      // Archive deleted records in a separate database table
      await connectionSchedule.execute('INSERT INTO archived_member_names (firstName, lastName, email, timestamp) SELECT firstName, lastName, email, timestamp FROM member_names WHERE timestamp < ?', [specifiedTimestamp]);
  
      await connectionSchedule.execute('DELETE FROM member_names WHERE timestamp < ?', [specifiedTimestamp]);
  
      console.log('Cron job executed: Deleted and archived scanned names.');
      // Reload the page after the cron job is executed
    } catch (error) {
      console.error('Error during cron job:', error.message);
    } finally {
      if (connectionSchedule) {
        connectionSchedule.release();
      }
    }
  });
  
  
  // ---------------------------------------------- End QR scanner page endpoint functionalities ----------------------------------------------
  
  
  // ---------------------------------------------- View member form page endpoint functionalities ----------------------------------------------
  // Gets all the members that have been subscribed
  app.get('/getUserProfileData', async (req, res) => {
    let connectionUserProfileData;
    try {
      connectionUserProfileData = await pool.getConnection();
  
      // Query to get user profile data including the number of bills, latest date_paid, and subscription_expiration
      const query = `
      SELECT 
      subscribed_members.subscribedId,
      subscribed_members.firstName,
      subscribed_members.lastName,
      subscribed_members.membershipType,
      COUNT(bills.bill_id) AS numberOfBills,
      IFNULL(MAX(bills.date_paid), 'pending') AS latestDatePaid,
      IFNULL(MAX(bills.subscription_expiration), 'pending') AS subscriptionExpiration
    FROM subscribed_members
    LEFT JOIN bills ON subscribed_members.subscribedId = bills.userId
    GROUP BY
      subscribed_members.subscribedId,
      subscribed_members.firstName,
      subscribed_members.lastName,
      subscribed_members.membershipType;  
      `;
  
      const [userProfileData] = await pool.execute(query);
  
      res.json(userProfileData);
    } catch (error) {
      console.error('Error fetching user profile data:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionUserProfileData) {
        connectionUserProfileData.release();
      }
    }
  });
  
  // ---------------------------------------------- End view member form page endpoint functionalities ----------------------------------------------
  
  
  // ---------------------------------------------- Application form page endpoint functionalities ----------------------------------------------
  //Gets the users who registered but isn't subscribed yet
  app.get('/getAllUsers', async (req, res) => {
    let connectionGetAllUsers;
    try {
      connectionGetAllUsers = await pool.getConnection();
      const query = `
        SELECT users.id, users.firstName, users.lastName, users.email,
               subscribed_members.userId AS subscribedUserId
        FROM users
        LEFT JOIN subscribed_members ON users.id = subscribed_members.userId
      `;
      const [users] = await connectionGetAllUsers.execute(query);
      res.json(users);
    } catch (error) {
      console.error('Error fetching all users:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionGetAllUsers) {
        connectionGetAllUsers.release();
      }
    }
  });
  
  // Gets the user information based on the id
  app.get('/getUserInfo/:id', checkAuthenticatedAdmin, async (req, res) => {
    const userId = req.params.id;
  
    let connectionGetUserInfo;
  
    try {
      connectionGetUserInfo = await pool.getConnection();
      const [rows] = await connectionGetUserInfo.execute('SELECT * FROM users WHERE id = ?', [userId]);
      const userData = rows[0];
  
      if (userData) {
        // Send the user data as a JSON response
        res.json(userData);
      } else {
        // User with the given ID not found
        res.status(404).json({ error: 'User not found' });
      }
    } catch (error) {
      console.error('Error fetching user information:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionGetUserInfo) {
        connectionGetUserInfo.release();
      }
    }
  });
  
  // Checks if the user is subscribed
  app.get('/checkSubscription/:userId', async (req, res) => {
    let connectionCheckSubscription;
    try {
      connectionCheckSubscription = await pool.getConnection();
      const userId = req.params.userId;
  
      let query;
      let queryParams;
  
      if (userId === 'null' || userId === null || typeof userId === 'undefined') {
        // If userId is 'null', check by email
        const email = req.query.email; // Assuming the email is provided as a query parameter
        query = 'SELECT * FROM subscribed_members WHERE email = ? AND userId IS NULL';
        queryParams = [email];
      } else {
        // If userId is provided, check by userId
        query = 'SELECT * FROM subscribed_members WHERE userId = ?';
        queryParams = [userId];
      }
  
      // Perform a query to check if the user is already subscribed
      const [result] = await connectionCheckSubscription.execute(query, queryParams);
  
      if (result.length > 0) {
        // User is already subscribed
        res.json({ subscribed: true });
      } else {
        // User is not subscribed
        res.json({ subscribed: false });
      }
    } catch (error) {
      console.error('Error checking subscription:', error.message);
      res.json({ subscribed: false });
    } finally {
      if (connectionCheckSubscription) {
        connectionCheckSubscription.release();
      }
    }
  });
  
  /* Used to submit the membership form in the application form page,
  this is from when the user is already registed*/
  app.post('/submitMembership/:userId', async (req, res) => {
    let connectionSubmitMembership;
  
    try {
      const userId = req.params.userId;
  
      // Check if the user is already subscribed
      const subscriptionCheckResponse = await fetch(`${req.protocol}://${req.get('host')}/checkSubscription/${userId}`);
      
      if (!subscriptionCheckResponse.ok) {
        throw new Error(`Error checking subscription: ${subscriptionCheckResponse.statusText}`);
      }
  
      const { subscribed } = await subscriptionCheckResponse.json();
  
      if (subscribed) {
        console.log('User is already subscribed');
        res.json({ success: false, message: 'User is already subscribed' });
        return;
      }
  
      // If not subscribed, proceed with form submission
      const { firstName, lastName, membershipType, email, contactNumber } = req.body;
      // Perform a query to insert data into the subscribed-members table
      connectionSubmitMembership = await pool.getConnection();
      const [result] = await connectionSubmitMembership.execute(
        'INSERT INTO subscribed_members (userId, firstName, lastName, membershipType, email, contactNumber) VALUES (?, ?, ?, ?, ?, ?)',
        [userId, firstName, lastName, membershipType, email, contactNumber]
      );
      
      // Update users with the new contactNumber
      await connectionSubmitMembership.execute(
        'UPDATE users SET contactNumber = ? WHERE id = ?',
        [contactNumber, userId]
      );
  
      if (result.affectedRows > 0) {
        console.log('Membership submitted successfully');
        res.json({ success: true });
      } else {
        console.error('Failed to submit membership');
        res.json({ success: false });
      }
    } catch (error) {
      console.error('Error during membership submission:', error.message);
      res.json({ success: false });
    } finally {
      if (connectionSubmitMembership) {
        connectionSubmitMembership.release();
      }
    }
  });
  
  /* Used to submit the membership form in the application form page,
  this is from when the admin fills the form manually*/
  app.post('/createUser', async (req, res) => {
    let connectionCreateUser;
    try {
        const { firstName, lastName, email, contactNumber, membershipType } = req.body;
        // Check if the user is already subscribed
        const subscriptionCheck = await checkSubscriptionByEmail(email);
        if (subscriptionCheck.subscribed) {
            // User is already subscribed
            req.flash('error', 'User is already subscribed');
            res.json({ success: false, message: 'User is already subscribed' });
            return;
        }
        // Insert data into subscribed_members
        connectionCreateUser = await pool.getConnection();
        const [result] = await pool.execute('INSERT INTO subscribed_members (firstName, lastName, email, contactNumber, membershipType) VALUES (?, ?, ?, ?, ?)', [firstName, lastName, email, contactNumber, membershipType]);
        if (result.affectedRows > 0) {
          console.log('Membership submitted successfully');
          res.json({ success: true });
        } else {
          console.error('Failed to submit membership');
          res.json({ success: false });
        }
    } catch (error) {
      console.error('Error during membership submission:', error.message);
      res.json({ success: false });
    } finally {
        if (connectionCreateUser) {
            connectionCreateUser.release();
        }
    }
  });
  
  async function checkSubscriptionByEmail(email) {
    let connectionCheckSubscription;
    try {
        connectionCheckSubscription = await pool.getConnection();
        // Perform a query to check if the user is already subscribed
        const [result] = await connectionCheckSubscription.execute('SELECT * FROM subscribed_members WHERE email = ?', [email]);
  
        if (result.length > 0) {
            // User is already subscribed
            return { subscribed: true };
        } else {
            // User is not subscribed
            return { subscribed: false };
        }
    } catch (error) {
        console.error('Error checking subscription:', error.message);
        return { subscribed: false };
    } finally {
        if (connectionCheckSubscription) {
            connectionCheckSubscription.release();
        }
    }
  }
  
  // ---------------------------------------------- End application form page endpoint functionalities ----------------------------------------------
  
  
  // ---------------------------------------------- Announcement page endpoint functionalities ----------------------------------------------
  // Gets the announcements stored in the database
  app.get('/get_announcements', async (req, res) => {
    let connectionGetAnnouncements;
    try {
        connectionGetAnnouncements = await pool.getConnection();
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
  
  // Submission of announcements
  app.post('/submit_announcement', async (req, res) => {
    let connectionSubmitAnnouncement;
    try {
      connectionSubmitAnnouncement = await pool.getConnection();
      const { category, title, content } = req.body;
  
      
  
      const result = await connectionSubmitAnnouncement.execute(
        'INSERT INTO announcements (category, title, content) VALUES (?, ?, ?)',
        [category, title, content]
      );
      
  
      if (result[0].affectedRows > 0) {
        //announcement submitted successfully
        console.log('Announcement submitted successfully');
        res.json({ success: true });
      } else {
        //announcement submission failed
        console.log('Failed to save announcement to the database. No rows affected.');
        res.status(500).json({ error: 'Failed to save announcement' });
      }
    } catch (error) {
      console.error('Error submitting announcement:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionSubmitAnnouncement){
        connectionSubmitAnnouncement.release();
      }
    }
  });
  
  // Editing an announcement
  app.put('/edit_announcement/:id', async (req, res) => {
    const announcementId = req.params.id;
    const { category, title, content } = req.body;
    
    let connectionEditAnnouncement;
  
    try {
      connectionEditAnnouncement = await pool.getConnection();
      const result = await connectionEditAnnouncement.execute(
        'UPDATE announcements SET category = ?, title = ?, content = ? WHERE id = ?',
        [category, title, content, announcementId]
      );
  
      if (result.affectedRows > 0) {
        // Announcement edited successfully
        res.json({ success: true, message: 'Announcement edited successfully' });
      } else {
        // Announcement with the given ID not found
        res.status(404).json({ error: 'Announcement not found' });
      }
    } catch (error) {
      console.error('Error editing announcement:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionEditAnnouncement){
        connectionEditAnnouncement.release();
      }
    }
  });
  
  // Deleting an announcement
  app.delete('/delete_announcement/:id', async (req, res) => {
    const announcementId = req.params.id;
  
    let connectionDeleteAnnouncement;
  
    try {
      connectionDeleteAnnouncement = await pool.getConnection();
      const result = await connectionDeleteAnnouncement.execute(
        'DELETE FROM announcements WHERE id = ?',
        [announcementId]
      );
  
      if (result.affectedRows > 0) {
        // Announcement deleted successfully
        res.json({ success: true, message: 'Announcement deleted successfully' });
      } else {
        // Announcement with the given ID not found
        res.status(404).json({ error: 'Announcement not found' });
      }
    } catch (error) {
      console.error('Error deleting announcement:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally { 
      if (connectionDeleteAnnouncement){
        connectionDeleteAnnouncement.release();
      }
    }
  });
  
  // ---------------------------------------------- End announcement page endpoint functionalities ----------------------------------------------
  
  
  // ---------------------------------------------- Billing page endpoint functionalities ----------------------------------------------
  // Endpoint to fetch user details based on user ID
  app.get('/getUserDetails/:subscribedId', async (req, res) => {
    const subscribedId = req.params.subscribedId;
    let connectionGetUserDetails;
  
    try {
      connectionGetUserDetails = await pool.getConnection();
      const [userResult] = await connectionGetUserDetails.execute('SELECT subscribedId, membershipType FROM subscribed_members WHERE subscribedId = ?', [subscribedId]);
  
      res.json(userResult[0]); // Send user details as JSON response
    } catch (error) {
      console.error('Error fetching user details:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionGetUserDetails) {
        connectionGetUserDetails.release();
      }
    }
  });
  
  // Gets all the subscribed members
  app.get('/getAllSubscribedUsers', async (req, res) => {
    let connectionGetAllSubscribedUsers;
  
    try {
      connectionGetAllSubscribedUsers = await pool.getConnection();
      const [users] = await connectionGetAllSubscribedUsers.execute('SELECT subscribedId, firstName, lastName, membershipType FROM subscribed_members');
  
      res.json(users); // Send all users as JSON response
    } catch (error) {
      console.error('Error fetching all users:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionGetAllSubscribedUsers) {
        connectionGetAllSubscribedUsers.release();
      }
    }
  });
  
  // Handls the creation of bills
  app.post('/createBill', async (req, res) => {
    const userId = req.body.userId;
    const datePaid = req.body.datePaid;
    const amount = req.body.amount;
    let connectionCreateBill;
  
    try {
      connectionCreateBill = await pool.getConnection();
  
      // Fetch user details including membership type from the /getAllSubscribedUsers endpoint
      const [userResult] = await connectionCreateBill.execute('SELECT subscribedId, membershipType FROM subscribed_members WHERE subscribedId = ?', [userId]);
  
      // Extract the necessary details
      const { membershipType } = userResult[0];
  
      // Parse the formatted date 'MM/DD/YY' to a JavaScript Date object
      const datePaidObject = new Date(datePaid);
  
      // Calculate subscription expiration (one month after the date paid)
      const subscriptionExpiration = new Date(datePaidObject.setMonth(datePaidObject.getMonth() + 1));
  
      // Format subscriptionExpiration as 'YYYY-MM-DD'
      const formattedSubscriptionExpiration = subscriptionExpiration.toISOString().split('T')[0];
  
      // Insert the bill into the bills table
      await connectionCreateBill.execute(
        'INSERT INTO bills (userId, membershipType, date_paid, subscription_expiration, amount) VALUES (?, ?, ?, ?, ?)',
        [userId, membershipType, datePaid, formattedSubscriptionExpiration, amount]
      );
  
      res.json({ success: true, message: 'Bill uploaded successfully' });
    } catch (error) {
      console.error('Error inserting bill:', error.message);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
    } finally {
      if (connectionCreateBill) {
        connectionCreateBill.release();
      }
    }
  });
  
  // Fetches all the bills to populate the table
  app.get('/getAllBills', async (req, res) => {
    let connectionGetAllBills;
    try {
      connectionGetAllBills = await pool.getConnection();
      const [bills] = await pool.execute('SELECT bills.*, subscribed_members.firstName, subscribed_members.lastName FROM bills JOIN subscribed_members ON bills.userId = subscribed_members.subscribedId');
      const billsWithUserName = bills.map(bill => ({
        userName: `${bill.firstName} ${bill.lastName}`,
        membershipType: bill.membershipType,
        datePaid: bill.date_paid,
        subscriptionExpiration: bill.subscription_expiration,
        amount: bill.amount,
      }));
      res.json(billsWithUserName);
    } catch (error) {
      console.error('Error fetching all bills:', error.message);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      if (connectionGetAllBills) {
        connectionGetAllBills.release();
      }
    }
  });
  
  // ---------------------------------------------- End billing page endpoint functionalities ----------------------------------------------
  
  
  // ---------------------------------------------- Accounting page endpoint functionalities ----------------------------------------------
  // Endpoint to get monthly transactions
  // Used also in index-admin.ejs
  app.get('/getMonthlyTransactions', async (req, res) => {
    let connectionGetMonthlyTransactions;
    try {
      connectionGetMonthlyTransactions = await pool.getConnection();
      const [monthlyData] = await connectionGetMonthlyTransactions.execute('SELECT * FROM monthly_transactions');
      res.json({ monthlyData });
    } catch (error) {
      console.error('Error getting monthly transactions:', error.message);
      res.status(500).json({ success: false, error: 'Internal Server Error' });
    } finally {
      if (connectionGetMonthlyTransactions){
        connectionGetMonthlyTransactions.release();
      }
    }
  });
  
  // Saves the monthly transactions
  app.post('/saveMonthlyTransactions', async (req, res) => {
    let connectionSaveMonthlyTransactions;
  
    try {
      const { monthlyData: newMonthlyData } = req.body;
  
      connectionSaveMonthlyTransactions = await pool.getConnection();
      await connectionSaveMonthlyTransactions.beginTransaction();
  
      // Use a loop to process each monthly data
      for (const data of newMonthlyData) {
        const {
          month,
          waterBill,
          electricBill,
          drinkableWaterBill,
          productSales,
          subscription,
          walkIn,
          monthlyExpense,
          monthlyIncome,
        } = data;
  
        try {
          // Check if the record already exists for the given month
          const [existingRows] = await connectionSaveMonthlyTransactions.execute(
            'SELECT * FROM monthly_transactions WHERE month = ?',
            [month]
          );
  
          if (existingRows.length > 0) {
            // Update the existing record
            const [updateResult] = await connectionSaveMonthlyTransactions.execute(
              'UPDATE monthly_transactions SET waterBill=?, electricBill=?, drinkableWaterBill=?, productSales=?, subscription=?, walkIn=?, monthlyExpense=?, monthlyIncome=? WHERE month=?',
              [
                waterBill,
                electricBill,
                drinkableWaterBill,
                productSales,
                subscription,
                walkIn,
                monthlyExpense,
                monthlyIncome,
                month,
              ]
            );
  
            if (updateResult.affectedRows > 0) {
              console.log(`Monthly transactions for ${month} updated successfully`);
            } else {
              console.error(`Failed to update monthly transactions for ${month}`);
            }
          } else {
            // Insert a new record
            const [insertResult] = await connectionSaveMonthlyTransactions.execute(
              'INSERT INTO monthly_transactions (month, waterBill, electricBill, drinkableWaterBill, productSales, subscription, walkIn, monthlyExpense, monthlyIncome) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
              [
                month,
                waterBill,
                electricBill,
                drinkableWaterBill,
                productSales,
                subscription,
                walkIn,
                monthlyExpense,
                monthlyIncome,
              ]
            );
  
            if (insertResult.affectedRows > 0) {
              console.log(`Monthly transactions for ${month} inserted successfully`);
            } else {
              console.error(`Failed to insert monthly transactions for ${month}`);
            }
          }
        } catch (error) {
          console.error(`Error processing data for month ${month}: ${error.message}`);
          throw error; // Re-throw the error to trigger a rollback
        }
      }
  
      // Commit the transaction if all data is processed successfully
      await connectionSaveMonthlyTransactions.commit();
  
      // Update the server data after successful transaction
      monthlyData = newMonthlyData;
  
      res.json({ success: true, message: 'Monthly transactions saved successfully' });
    } catch (error) {
      console.error('Error saving monthly transactions:', error.message);
  
      // Rollback the transaction on error
      if (connectionSaveMonthlyTransactions) {
        await connectionSaveMonthlyTransactions.rollback();
      }
  
      res.status(500).json({ success: false, error: 'Internal Server Error' });
    } finally {
      if (connectionSaveMonthlyTransactions) {
        connectionSaveMonthlyTransactions.release();
      }
    }
  });
  
  // ---------------------------------------------- End accounting page endpoint functionalities ----------------------------------------------
  
  // ---------------------------------------------- USER SIDE ----------------------------------------------

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
  
      connectionUserRegister = await pool.getConnection();
  
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
      connectionBillingHistory = await pool.getConnection();
  
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
      connectionUpdateUser = await pool.getConnection();
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
      connectionUpdatePassword = await pool.getConnection();
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

  // Handle graceful shutdown
  process.on('SIGINT', async () => {
    console.log('Received SIGINT. Closing server gracefully...');
    
    // Close the database connection pool
    await pool.end();
    
    // Exit the process
    process.exit();
  });
  
  // Start the server
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });