const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());

app.use(cors({
  origin: '*', 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const prisma = new PrismaClient();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

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

app.post('/api/register', async (req, res) => {
  try {
    const { fullName, phone, email, password, lga, village, farmSizeHa } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    const lastFarmer = await prisma.user.findFirst({ orderBy: { farmerId: 'desc' } });
    const nextNum = lastFarmer ? parseInt(lastFarmer.farmerId.split('-')[1]) + 1 : 1;
    const farmerId = `CRYAM-${nextNum.toString().padStart(4, '0')}`;

    const user = await prisma.user.create({
      data: { farmerId, fullName, phone, email, password: hashed, role: 'FARMER', lga, village, farmSizeHa }
    });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, farmerId: user.farmerId, fullName: user.fullName, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;
  const user = await prisma.user.findUnique({ where: { phone } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, farmerId: user.farmerId, fullName: user.fullName, role: user.role } });
});

app.get('/api/profile', authenticate, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  res.json(user);
});

app.post('/api/production', authenticate, async (req, res) => {
  const { year, season, productionTonnes } = req.body;
  try {
    const setting = await prisma.setting.findUnique({ where: { id: 'tax_rate' } });
    if (!setting) return res.status(500).json({ error: "Tax rate not configured." });

    const taxDue = parseFloat(productionTonnes) * setting.taxRatePerTonne;
    const prod = await prisma.production.create({
      data: { userId: req.user.id, year: parseInt(year), season, productionTonnes: parseFloat(productionTonnes), taxDue }
    });
    res.json(prod);
  } catch (err) {
    res.status(500).json({ error: "Failed to record production" });
  }
});

app.get('/api/production', authenticate, async (req, res) => {
  const prods = await prisma.production.findMany({
    where: { userId: req.user.id },
    include: { payments: true }
  });
  res.json(prods);
});

app.post('/api/payment', authenticate, async (req, res) => {
  const { productionId, amount, reference } = req.body;
  try {
    const payment = await prisma.payment.create({
      data: { productionId, amount: parseFloat(amount), reference: reference || null }
    });
    res.json(payment);
  } catch (err) {
    res.status(500).json({ error: "Payment failed" });
  }
});

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

  res.json({ 
    totalFarmers, 
    totalProduction: totalProduction._sum.productionTonnes || 0, 
    totalTaxDue: totalTaxDue._sum.taxDue || 0, 
    totalCollected: totalCollected._sum.amount || 0, 
    byLga 
  });
});

app.put('/api/admin/tax-rate', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const { rate } = req.body;
  await prisma.setting.update({ where: { id: 'tax_rate' }, data: { taxRatePerTonne: parseFloat(rate) } });
  res.json({ message: 'Tax rate updated' });
});

app.get('/api/admin/payments', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  try {
    const payments = await prisma.payment.findMany({
      include: {
        production: { include: { user: true } }
      },
      orderBy: { paymentDate: 'desc' }
    });
    res.json(payments);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch payments' });
  }
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));