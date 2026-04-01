const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({
  origin: '*',                    // Allow all origins (safe for development & early deployment)
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Register Farmer
app.post('/api/register', async (req, res) => {
  const { fullName, phone, email, password, lga, village, farmSizeHa } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  // Generate unique Farmer ID
  const lastFarmer = await prisma.user.findFirst({ orderBy: { farmerId: 'desc' } });
  const nextNum = lastFarmer ? parseInt(lastFarmer.farmerId.split('-')[1]) + 1 : 1;
  const farmerId = `CRYAM-${nextNum.toString().padStart(4, '0')}`;

  const user = await prisma.user.create({
    data: { farmerId, fullName, phone, email, password: hashed, role: 'FARMER', lga, village, farmSizeHa }
  });

  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, farmerId: user.farmerId, fullName: user.fullName, role: user.role } });
});

// Login
app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;
  const user = await prisma.user.findUnique({ where: { phone } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, farmerId: user.farmerId, fullName: user.fullName, role: user.role } });
});

// Get current user profile
app.get('/api/profile', authenticate, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  res.json(user);
});

// Record Production + Auto Tax
app.post('/api/production', authenticate, async (req, res) => {
  const { year, season, productionTonnes } = req.body;

  // Convert to number safely
  const tonnes = parseFloat(productionTonnes);
  if (isNaN(tonnes) || tonnes <= 0) {
    return res.status(400).json({ error: "Production tonnes must be a valid positive number" });
  }

  try {
    const setting = await prisma.setting.findUnique({ where: { id: 'tax_rate' } });
    
    if (!setting) {
      return res.status(500).json({ error: "Tax rate not configured. Please contact admin." });
    }

    const taxDue = tonnes * setting.taxRatePerTonne;

    const prod = await prisma.production.create({
      data: {
        userId: req.user.id,
        year: parseInt(year),
        season,
        productionTonnes: tonnes,     // ← Now properly as Float
        taxDue
      }
    });

    res.json(prod);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to record production" });
  }
});

// Get farmer's productions
app.get('/api/production', authenticate, async (req, res) => {
  const prods = await prisma.production.findMany({
    where: { userId: req.user.id },
    include: { payments: true }
  });
  res.json(prods);
});

// Record Payment
app.post('/api/payment', authenticate, async (req, res) => {
  const { productionId, amount, reference } = req.body;
  const payment = await prisma.payment.create({
    data: { productionId, amount, reference }
  });
  res.json(payment);
});

// Record Tax Payment
app.post('/api/payment', authenticate, async (req, res) => {
  const { productionId, amount, reference } = req.body;

  if (!productionId || !amount || amount <= 0) {
    return res.status(400).json({ error: "Invalid payment data" });
  }

  try {
    const payment = await prisma.payment.create({
      data: {
        productionId,
        amount: parseFloat(amount),
        reference: reference || null
      }
    });

    res.json({ message: "Payment recorded successfully", payment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to record payment" });
  }
});

// ADMIN ROUTES
app.get('/api/admin/farmers', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const farmers = await prisma.user.findMany({ where: { role: 'FARMER' } });
  res.json(farmers);
});

app.get('/api/admin/reports', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const totalFarmers = await prisma.user.count({ where: { role: 'FARMER' } });
  const totalProduction = await prisma.production.aggregate({ _sum: { productionTonnes: true } });
  const totalTaxDue = await prisma.production.aggregate({ _sum: { taxDue: true } });
  const totalCollected = await prisma.payment.aggregate({ _sum: { amount: true } });

  const byLga = await prisma.user.groupBy({
    by: ['lga'],
    _count: { id: true }
  });

  res.json({ totalFarmers, totalProduction: totalProduction._sum.productionTonnes || 0, totalTaxDue: totalTaxDue._sum.taxDue || 0, totalCollected: totalCollected._sum.amount || 0, byLga });
});

// Update tax rate (Admin only)
app.put('/api/admin/tax-rate', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const { rate } = req.body;
  await prisma.setting.update({ where: { id: 'tax_rate' }, data: { taxRatePerTonne: rate } });
  res.json({ message: 'Tax rate updated' });
});


// Get All Payments (Admin only)
app.get('/api/admin/payments', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });

  try {
    const payments = await prisma.payment.findMany({
      include: {
        production: {
          include: {
            user: true
          }
        }
      },
      orderBy: { paymentDate: 'desc' }
    });
    res.json(payments);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch payments' });
  }
});

app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));