const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Configuration, PlaidApi, PlaidEnvironments } = require('plaid');
const { Pool } = require('pg');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Plaid configuration
const plaidConfig = new Configuration({
  basePath: PlaidEnvironments[process.env.PLAID_ENV || 'sandbox'],
  baseOptions: {
    headers: {
      'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID,
      'PLAID-SECRET': process.env.PLAID_SECRET,
    },
  },
});

const plaidClient = new PlaidApi(plaidConfig);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ==================== AUTH ROUTES ====================

// Register new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Check if user exists
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = await pool.query(
      'INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name',
      [email, hashedPassword, name]
    );

    const user = result.rows[0];

    // Generate JWT
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '7d'
    });

    res.json({ token, user });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '7d'
    });

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================== PLAID ROUTES ====================

// Create Link Token (for connecting banks)
app.post('/api/plaid/create-link-token', authenticateToken, async (req, res) => {
  try {
    const response = await plaidClient.linkTokenCreate({
      user: {
        client_user_id: req.user.id.toString(),
      },
      client_name: 'Cash Flow Tracker',
      products: ['auth', 'transactions'],
      country_codes: ['US'],
      language: 'en',
    });

    res.json({ link_token: response.data.link_token });
  } catch (error) {
    console.error('Link token creation error:', error);
    res.status(500).json({ error: 'Failed to create link token' });
  }
});

// Exchange public token for access token
app.post('/api/plaid/exchange-public-token', authenticateToken, async (req, res) => {
  try {
    const { public_token } = req.body;

    // Exchange public token
    const response = await plaidClient.itemPublicTokenExchange({
      public_token: public_token,
    });

    const accessToken = response.data.access_token;
    const itemId = response.data.item_id;

    // Get account details
    const accountsResponse = await plaidClient.accountsGet({
      access_token: accessToken,
    });

    const institution = accountsResponse.data.item.institution_id;

    // Store access token (encrypted in production)
    await pool.query(
      'INSERT INTO plaid_items (user_id, access_token, item_id, institution_id) VALUES ($1, $2, $3, $4)',
      [req.user.id, accessToken, itemId, institution]
    );

    // Store accounts
    for (const account of accountsResponse.data.accounts) {
      await pool.query(
        'INSERT INTO accounts (user_id, plaid_account_id, item_id, name, type, subtype, mask) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [req.user.id, account.account_id, itemId, account.name, account.type, account.subtype, account.mask]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Token exchange error:', error);
    res.status(500).json({ error: 'Failed to exchange token' });
  }
});

// Get all accounts and balances
app.get('/api/accounts', authenticateToken, async (req, res) => {
  try {
    // Get all Plaid items for this user
    const itemsResult = await pool.query(
      'SELECT * FROM plaid_items WHERE user_id = $1',
      [req.user.id]
    );

    const allAccounts = [];
    let totalBankBalance = 0;
    let totalCreditBalance = 0;

    // Fetch balances for each item
    for (const item of itemsResult.rows) {
      try {
        const balanceResponse = await plaidClient.accountsBalanceGet({
          access_token: item.access_token,
        });

        for (const account of balanceResponse.data.accounts) {
          const accountData = {
            id: account.account_id,
            name: account.name,
            type: account.type,
            subtype: account.subtype,
            mask: account.mask,
            balance: account.balances.available || account.balances.current,
            limit: account.balances.limit,
            current: account.balances.current,
          };

          // Calculate credit card balance (Limit - Available)
          if (account.type === 'credit') {
            const creditLimit = account.balances.limit || 0;
            const availableCredit = account.balances.available || 0;
            const creditBalance = creditLimit - availableCredit;
            
            accountData.creditBalance = creditBalance;
            accountData.availableCredit = availableCredit;
            totalCreditBalance += creditBalance;
          } else {
            // For bank accounts, use available balance
            totalBankBalance += (account.balances.available || account.balances.current || 0);
          }

          allAccounts.push(accountData);

          // Update balance in database
          await pool.query(
            'UPDATE accounts SET last_balance = $1, last_updated = NOW() WHERE plaid_account_id = $2',
            [account.balances.current, account.account_id]
          );
        }
      } catch (error) {
        console.error(`Error fetching balances for item ${item.item_id}:`, error);
      }
    }

    // Calculate net available cash: Bank balances - Credit card balances
    const netAvailableCash = totalBankBalance - totalCreditBalance;

    res.json({
      accounts: allAccounts,
      summary: {
        totalBankBalance: totalBankBalance.toFixed(2),
        totalCreditBalance: totalCreditBalance.toFixed(2),
        netAvailableCash: netAvailableCash.toFixed(2),
      },
    });
  } catch (error) {
    console.error('Error fetching accounts:', error);
    res.status(500).json({ error: 'Failed to fetch accounts' });
  }
});

// Remove/delete a linked account
app.delete('/api/plaid/item/:itemId', authenticateToken, async (req, res) => {
  try {
    const { itemId } = req.params;

    // Get access token
    const result = await pool.query(
      'SELECT access_token FROM plaid_items WHERE item_id = $1 AND user_id = $2',
      [itemId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Item not found' });
    }

    // Remove from Plaid
    await plaidClient.itemRemove({
      access_token: result.rows[0].access_token,
    });

    // Delete from database
    await pool.query('DELETE FROM accounts WHERE item_id = $1 AND user_id = $2', [itemId, req.user.id]);
    await pool.query('DELETE FROM plaid_items WHERE item_id = $1 AND user_id = $2', [itemId, req.user.id]);

    res.json({ success: true });
  } catch (error) {
    console.error('Error removing item:', error);
    res.status(500).json({ error: 'Failed to remove item' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

