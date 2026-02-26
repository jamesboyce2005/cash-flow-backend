const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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

// ==================== ACCOUNT ROUTES ====================

// Get all accounts
app.get('/api/accounts', authenticateToken, async (req, res) => {
  try {
    const accountsResult = await pool.query(
      `SELECT 
        id,
        name, 
        type, 
        last_balance,
        credit_limit,
        custom_name, 
        hidden, 
        display_order,
        last_updated
      FROM accounts
      WHERE user_id = $1 
      ORDER BY display_order`,
      [req.user.id]
    );

    let totalBankBalance = 0;
    let totalCreditBalance = 0;

    const accounts = accountsResult.rows.map(acc => {
      const account = {
        id: acc.id,
        name: acc.name,
        type: acc.type,
        balance: parseFloat(acc.last_balance) || 0,
        custom_name: acc.custom_name,
        hidden: acc.hidden,
        display_order: acc.display_order,
        last_updated: acc.last_updated,
      };

      // Calculate totals (exclude hidden accounts)
      if (!acc.hidden) {
        if (acc.type === 'credit') {
          const creditLimit = parseFloat(acc.credit_limit) || 0;
          const balance = parseFloat(acc.last_balance) || 0;
          
          account.limit = creditLimit;
          account.creditBalance = balance;
          account.availableCredit = creditLimit - balance;
          totalCreditBalance += balance;
        } else {
          // Bank accounts (checking, savings)
          totalBankBalance += parseFloat(acc.last_balance) || 0;
        }
      }

      return account;
    });

    const netAvailableCash = totalBankBalance - totalCreditBalance;

    res.json({
      accounts,
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

// Create new account
app.post('/api/accounts', authenticateToken, async (req, res) => {
  try {
    const { name, type, balance, credit_limit } = req.body;

    // Get the highest display_order to put new account at the end
    const orderResult = await pool.query(
      'SELECT COALESCE(MAX(display_order), -1) + 1 as next_order FROM accounts WHERE user_id = $1',
      [req.user.id]
    );
    const displayOrder = orderResult.rows[0].next_order;

    const result = await pool.query(
      `INSERT INTO accounts (user_id, name, type, last_balance, credit_limit, display_order, last_updated) 
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
       RETURNING *`,
      [req.user.id, name, type, balance || 0, credit_limit, displayOrder]
    );

    res.json({ account: result.rows[0] });
  } catch (error) {
    console.error('Error creating account:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Update account balance
app.patch('/api/accounts/:accountId/balance', authenticateToken, async (req, res) => {
  try {
    const { accountId } = req.params;
    const { balance } = req.body;

    const result = await pool.query(
      'UPDATE accounts SET last_balance = $1, last_updated = NOW() WHERE id = $2 AND user_id = $3 RETURNING *',
      [balance, accountId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    res.json({ account: result.rows[0] });
  } catch (error) {
    console.error('Error updating balance:', error);
    res.status(500).json({ error: 'Failed to update balance' });
  }
});

// Delete account
app.delete('/api/accounts/:accountId', authenticateToken, async (req, res) => {
  try {
    const { accountId } = req.params;

    const result = await pool.query(
      'DELETE FROM accounts WHERE id = $1 AND user_id = $2 RETURNING *',
      [accountId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Hide/show account
app.patch('/api/accounts/:accountId/toggle-hide', authenticateToken, async (req, res) => {
  try {
    const { accountId } = req.params;
    
    const result = await pool.query(
      'UPDATE accounts SET hidden = NOT hidden WHERE id = $1 AND user_id = $2 RETURNING hidden',
      [accountId, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    res.json({ hidden: result.rows[0].hidden });
  } catch (error) {
    console.error('Error toggling account visibility:', error);
    res.status(500).json({ error: 'Failed to update account' });
  }
});

// Rename account
app.patch('/api/accounts/:accountId/rename', authenticateToken, async (req, res) => {
  try {
    const { accountId } = req.params;
    const { customName } = req.body;
    
    await pool.query(
      'UPDATE accounts SET custom_name = $1 WHERE id = $2 AND user_id = $3',
      [customName, accountId, req.user.id]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error renaming account:', error);
    res.status(500).json({ error: 'Failed to rename account' });
  }
});

// Update account display order
app.patch('/api/accounts/reorder', authenticateToken, async (req, res) => {
  try {
    const { accountOrders } = req.body; // Array of {accountId, order}
    
    for (const item of accountOrders) {
      await pool.query(
        'UPDATE accounts SET display_order = $1 WHERE id = $2 AND user_id = $3',
        [item.order, item.accountId, req.user.id]
      );
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating account order:', error);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// ==================== BILLS ROUTES ====================

// Get bills for current month
app.get('/api/bills', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const month = now.getMonth() + 1;
    const year = now.getFullYear();
    
    const result = await pool.query(
      'SELECT * FROM bills WHERE user_id = $1 AND month = $2 AND year = $3 ORDER BY due_day',
      [req.user.id, month, year]
    );
    
    res.json({ bills: result.rows });
  } catch (error) {
    console.error('Error fetching bills:', error);
    res.status(500).json({ error: 'Failed to fetch bills' });
  }
});

// Create bill
app.post('/api/bills', authenticateToken, async (req, res) => {
  try {
    const { name, amount, due_day } = req.body;
    const now = new Date();
    const month = now.getMonth() + 1;
    const year = now.getFullYear();
    
    const result = await pool.query(
      'INSERT INTO bills (user_id, name, amount, due_day, month, year) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.user.id, name, amount, due_day, month, year]
    );
    
    res.json({ bill: result.rows[0] });
  } catch (error) {
    console.error('Error creating bill:', error);
    res.status(500).json({ error: 'Failed to create bill' });
  }
});

// Toggle bill paid status
app.patch('/api/bills/:billId/toggle-paid', authenticateToken, async (req, res) => {
  try {
    const { billId } = req.params;
    
    const result = await pool.query(
      'UPDATE bills SET is_paid = NOT is_paid WHERE id = $1 AND user_id = $2 RETURNING is_paid',
      [billId, req.user.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Bill not found' });
    }
    
    res.json({ is_paid: result.rows[0].is_paid });
  } catch (error) {
    console.error('Error toggling bill status:', error);
    res.status(500).json({ error: 'Failed to update bill' });
  }
});

// Delete bill
app.delete('/api/bills/:billId', authenticateToken, async (req, res) => {
  try {
    const { billId } = req.params;
    
    await pool.query('DELETE FROM bills WHERE id = $1 AND user_id = $2', [billId, req.user.id]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting bill:', error);
    res.status(500).json({ error: 'Failed to delete bill' });
  }
});

// TEMPORARY: Database migration endpoint - remove after running once
app.get('/api/migrate', async (req, res) => {
  try {
    await pool.query('ALTER TABLE accounts ALTER COLUMN plaid_account_id DROP NOT NULL');
    await pool.query('ALTER TABLE accounts ALTER COLUMN item_id DROP NOT NULL');
    res.json({ success: true, message: 'Migration completed' });
  } catch (error) {
    console.error('Migration error:', error);
    res.status(500).json({ error: error.message });
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
