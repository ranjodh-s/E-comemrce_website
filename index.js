import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import cors from 'cors';
import path from 'path';
import bcrypt from 'bcrypt';
import session from 'express-session';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';
import dotenv from "dotenv";
import multer from 'multer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


dotenv.config();
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

db.connect();


const port = 3000;
const app = express();
// Temporary OTP store (in production use Redis or DB)
let otpStore = {};



// Define storage for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });



app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true
}));
app.use('/uploads', express.static('uploads'));
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    res.redirect('/login');
  }
}
function sellerAuth(req, res, next) {
  if (!req.session.seller) {
    return res.redirect('/seller/login');
  }
  next();
}





// GET: Sign up page
app.get('/', (req, res) => {
  res.redirect('/home')
});

app.get('/user/signup', (req, res) => {
  res.render('signup', { error: null })
})

// POST: Sign up logic
app.post('/user/signup', async (req, res) => {
  const { name, email, password, phone, address } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    await db.query(`
      INSERT INTO users (name, email, password, phone, address)
      VALUES ($1, $2, $3, $4, $5)
    `, [name, email, hashed, phone, address]);

    // Redirect to login
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.render('signup', { error: 'Signup failed. Try a different email.' });
  }
});

// GET: Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// POST: Login logic
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email=$1', [email]);
    if (result.rows.length === 0) {
      console.log(email)
      return res.render('login', { error: 'Invalid email or password.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {

      return res.render('login', { error: 'Invalid email or password.' });
    }

    // Save user in session
    req.session.user = {
      id: user.user_id,
      name: user.name,
      email: user.email
    };

    // Redirect to home
    res.redirect('/home');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Something went wrong!' });
  }
});



app.get('/forgot-password', async (req,res)=>{
  res.render("forgot_password.ejs")
})

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  console.log(email)

  // ✅ Check if email exists
  const result = await db.query('SELECT * FROM users WHERE email=$1', [email]);
  if (result.rows.length === 0) {
    return res.render('forgot_password', { error: '❌ Email not found.' });
  }

  // ✅ Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000);

  // ✅ Store OTP temporarily (5 mins expiry)
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  // ✅ Send OTP via email
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER , pass: process.env.EMAIL_PASS }
  });

  await transporter.sendMail({
    from: 'rnjodh039@gmail.com',
    to: email,
    subject: 'Your OTP for Password Reset',
    text: `Your OTP is ${otp}. It is valid for 5 minutes.`
  });

  res.render('verify_otp', { email });
});


app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) {
    return res.send('❌ OTP expired or invalid');
  }

  if (otpStore[email].otp != otp) {
    return res.send('❌ Incorrect OTP');
  }

  // ✅ OTP verified
  delete otpStore[email]; // remove used OTP
  res.render('reset_password', { email });
});



app.post('/reset-password', async (req, res) => {
  const { email, new_password, confirm_password } = req.body;

  if (new_password !== confirm_password) {
    return res.send('❌ Passwords do not match');
  }

  const hashed = await bcrypt.hash(new_password, 10);

  await db.query('UPDATE users SET password=$1 WHERE email=$2', [hashed, email]);

  res.send('✅ Password reset successful! You can now <a href="/login">login</a>.');
});



app.get('/home', async (req, res) => {
  try {
    // Get 10 random categories
    const catResult = await db.query(`
      SELECT category FROM products
      GROUP BY category
      ORDER BY RANDOM()
      LIMIT 10
    `);
    const categories = catResult.rows.map(row => row.category);

    // Get all products in those categories
    const prodResult = await db.query(`
      SELECT * FROM products WHERE category = ANY($1::text[])
      ORDER BY category, id
    `, [categories]);

    const productsByCategory = {};

    prodResult.rows.forEach(product => {
      const category = product.category;
      if (!productsByCategory[category]) {
        productsByCategory[category] = [];
      }
      productsByCategory[category].push(product);
    });
    let login = req.session.user ? true : false;

    res.render('home', { login, productsByCategory });


  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading homepage');
  }
});

app.get('/categories', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT DISTINCT category FROM products ORDER BY category
    `);
    const categories = result.rows.map(row => row.category);

    let login = req.session.user ? true : false;
    res.render('categories', { login, categories });
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to load categories');
  }
});


app.get('/category/:name', async (req, res) => {
  const category = req.params.name;
  try {
    const result = await db.query(`
      SELECT * FROM products WHERE category = $1
    `, [category]);

    let login = req.session.user ? true : false;
    res.render('category', { login, category, products: result.rows });;


  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to load category');
  }
});



app.get('/product/:id', async (req, res) => {
  const productId = req.params.id;

  try {
    const result = await db.query('SELECT * FROM products WHERE id = $1', [productId]);

    if (result.rows.length === 0) {
      return res.status(404).send('Product not found');
    }

    const product = result.rows[0];
    let login = req.session.user ? true : false;
    res.render('product', { login, product });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/cart/delete-ajax', async (req, res) => {
  const uid = req.session.user?.id;
  const { product_id } = req.body;

  if (!uid) return res.status(401).json({ success: false });

  try {
    await db.query(`
      DELETE FROM cart_items
      WHERE user_id = $1 AND product_id = $2
    `, [uid, product_id]);

    const totalResult = await db.query(`
      SELECT SUM(p.price * c.quantity) AS total
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = $1
    `, [uid]);

    res.json({ success: true, total: totalResult.rows[0].total || 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});



app.post('/cart/add', async (req, res) => {
  const uid = req.session.user.id;
  const { product_id } = req.body;

  try {
    await db.query(`
      INSERT INTO cart_items (user_id, product_id, quantity)
      VALUES ($1, $2, 1)
      ON CONFLICT (user_id, product_id)
      DO UPDATE SET quantity = cart_items.quantity + 1
    `, [uid, product_id]);

    res.json({ success: true, message: 'Item added to cart' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error adding item' });
  }
});



app.get('/cart', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const uid = req.session.user.id;

  const result = await db.query(`
    SELECT p.*, c.quantity FROM cart_items c
    JOIN products p ON c.product_id = p.id
    WHERE c.user_id = $1
  `, [uid]);
  let login = req.session.user ? true : false;
  res.render('cart', { login, cartItems: result.rows });
});

app.post('/cart/update-ajax', async (req, res) => {
  const uid = req.session.user?.id;
  const { product_id, action } = req.body;

  if (!uid) return res.status(401).json({ success: false });

  try {
    if (action === 'increase') {
      await db.query(`
        UPDATE cart_items SET quantity = quantity + 1
        WHERE user_id = $1 AND product_id = $2
      `, [uid, product_id]);
    } else if (action === 'decrease') {
      const result = await db.query(`
        SELECT quantity FROM cart_items WHERE user_id = $1 AND product_id = $2
      `, [uid, product_id]);

      if (result.rows[0]?.quantity <= 1) {
        await db.query(`
          DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2
        `, [uid, product_id]);
        return res.json({ removed: true });
      }

      await db.query(`
        UPDATE cart_items SET quantity = quantity - 1
        WHERE user_id = $1 AND product_id = $2
      `, [uid, product_id]);
    }

    const updatedItem = await db.query(`
      SELECT p.price, c.quantity FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = $1 AND c.product_id = $2
    `, [uid, product_id]);

    const { price, quantity } = updatedItem.rows[0];
    const subtotal = price * quantity;

    // get updated total
    const totalResult = await db.query(`
      SELECT SUM(p.price * c.quantity) AS total
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = $1
    `, [uid]);

    res.json({
      success: true,
      newQuantity: quantity,
      newSubtotal: subtotal,
      total: totalResult.rows[0].total || 0
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false });
  }
});



app.post('/cart/update', async (req, res) => {
  const uid = req.session.user.id;
  const { product_id, action } = req.body;

  if (action === 'increase') {
    await db.query(`
      UPDATE cart_items
      SET quantity = quantity + 1
      WHERE user_id = $1 AND product_id = $2
    `, [uid, product_id]);
  } else if (action === 'decrease') {
    const result = await db.query(`
      SELECT quantity FROM cart_items
      WHERE user_id = $1 AND product_id = $2
    `, [uid, product_id]);

    if (result.rows[0]?.quantity > 1) {
      await db.query(`
        UPDATE cart_items
        SET quantity = quantity - 1
        WHERE user_id = $1 AND product_id = $2
      `, [uid, product_id]);
    } else {
      await db.query(`
        DELETE FROM cart_items
        WHERE user_id = $1 AND product_id = $2
      `, [uid, product_id]);
    }
  }

  res.redirect('/cart');
});


app.post('/cart/delete', async (req, res) => {
  const uid = req.session.user.id;
  const { product_id } = req.body;

  await db.query(`
    DELETE FROM cart_items
    WHERE user_id = $1 AND product_id = $2
  `, [uid, product_id]);

  res.redirect('/cart');
});


app.get('/search', async (req, res) => {
  const query = req.query.q;
  try {
    const result = await db.query(`
      SELECT * FROM products
      WHERE name ILIKE $1 OR description ILIKE $1 OR category ILIKE $1
    `, [`%${query}%`]);


    let login = req.session.user ? true : false;

    res.render('results', { login, query, products: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.post('/buy', async (req, res) => {
  const user = req.session.user;
  if (!user) return res.redirect('/login');

  const { product_id, quantity = 1, payment_method = 'COD' } = req.body;

  // Get product price
  const result = await db.query(`SELECT price FROM products WHERE id = $1`, [product_id]);
  const price = result.rows[0].price;
  const total_price = price * quantity;

  // Insert into orders
  await db.query(`
    INSERT INTO orders (user_id, product_id, quantity, total_price, payment_method)
    VALUES ($1, $2, $3, $4, $5)
  `, [user.id, product_id, quantity, total_price, payment_method]);

  // ✅ Redirect back to same product page
  res.redirect(`/product/${product_id}`);
});


app.get('/orders', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const uid = req.session.user.id;
  const result = await db.query(`
    SELECT o.*, p.name, p.image_url, p.price
    FROM orders o
    JOIN products p ON o.product_id = p.id
    WHERE o.user_id = $1
    ORDER BY o.order_date DESC
  `, [uid]);
  let login = req.session.user ? true : false;

  res.render('orders', { login, orders: result.rows });
});


// GET Account Page
app.get('/account', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;

  try {
    const result = await db.query(
      'SELECT user_id, name, email, phone, address FROM users WHERE user_id = $1',
      [userId]
    );

    const user = result.rows[0];
    let login = req.session.user ? true : false;
    res.render('account', { login, user });
  } catch (err) {
    console.error('Error fetching user details:', err);
    res.status(500).send('Error loading account page');
  }
});


// POST Update Account Info
app.post('/account', async (req, res) => {
  const { name, email, phone, address } = req.body;
  const userId = req.session.user.id;

  try {
    await db.query(`
      UPDATE users SET name = $1, email = $2, phone = $3, address = $4
      WHERE user_id = $5
    `, [name, email, phone, address, userId]);

    // Update session info
    req.session.user.name = name;
    req.session.user.email = email;
    req.session.user.phone = phone;
    req.session.user.address = address;

    res.redirect('/account');
  } catch (err) {
    console.error(err);
    res.status(500).send("Error updating user info");
  }
});







app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout Error:', err);
      return res.status(500).send('Something went wrong while logging out.');
    }

    res.clearCookie('connect.sid'); // Optional: clears session cookie
    res.redirect('/home');
  });
});


app.get('/seller/signup', (req, res) => {
  res.render('seller_signup'); // matches signup.ejs
});

// POST route to handle form submission
app.post('/seller/signup', async (req, res) => {
  const { name, store_name, email, password, phone, address } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      `INSERT INTO sellers (name, store_name, email, password, phone, address)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [name, store_name, email, hashedPassword, phone, address]
    );

    res.redirect('/seller/login')
  } catch (err) {
    console.error('Signup Error:', err);
    res.status(500).send('Something went wrong!');
  }
});

// GET Login page
app.get('/seller/login', (req, res) => {
  res.render('seller_login', { error: null });
});

// POST Login form
app.post('/seller/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM sellers WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.render('seller_login', { error: 'Invalid email or password.' });
    }

    const seller = result.rows[0];
    const isMatch = await bcrypt.compare(password, seller.password);

    if (!isMatch) {
      return res.render('seller_login', { error: 'Invalid email or password.' });
    }

    // Save to session
    req.session.seller = {
      id: seller.seller_id,
      email: seller.email,
      store_name: seller.store_name
    };

    res.redirect('/seller/dashboard');
  } catch (err) {
    console.error(err);
    res.send('Login error');
  }
});

// GET Dashboard (Protected Route)
app.get('/seller/dashboard', sellerAuth, async (req, res) => {
  if (!req.session.seller) return res.redirect('/login');

  const sellerId = req.session.seller.id;

  try {
    const result = await db.query(`
      SELECT 
        p.id,
        p.name,
        COALESCE(SUM(o.quantity), 0) AS total_quantity_sold,
        COALESCE(SUM(o.total_price), 0) AS total_revenue,
        image_url
      FROM products p
      LEFT JOIN orders o ON p.id = o.product_id
      WHERE p.seller_id = $1
      GROUP BY p.id, p.name
      ORDER BY total_quantity_sold DESC;
    `, [sellerId]);

    res.render('seller-dashboard', { salesData: result.rows, seller: req.session.seller });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading dashboard');
  }
});

// GET Logout
app.get('/seller/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/seller/login');
});


// GET Edit Profile
app.get('/seller/edit-profile', sellerAuth, (req, res) => {
  if (!req.session.seller) return res.redirect('/seller/login');
  db.query('SELECT * FROM sellers WHERE seller_id=$1', [req.session.seller.id])
    .then(result => res.render('edit-profile', { seller: result.rows[0] }))
    .catch(err => res.send('Error loading profile'));
});

// POST Edit Profile
app.post('/seller/edit-profile', sellerAuth, async (req, res) => {
  const { name, store_name, phone, address } = req.body;
  await db.query(
    `UPDATE sellers SET name=$1, store_name=$2, phone=$3, address=$4 WHERE seller_id=$5`,
    [name, store_name, phone, address, req.session.seller.id]
  );
  req.session.seller.store_name = store_name; // Update session
  res.redirect('/seller/dashboard');
});

// GET Form
app.get('/seller/list-product', sellerAuth, (req, res) => {
  if (!req.session.seller) return res.redirect('/seller/login');
  res.render('list-product');
});

// POST Form Submission
app.post('/seller/add-product', sellerAuth, upload.single('image'), async (req, res) => {
  const {
    name, price, stock, category,
    description, brand, color, size,
    currency, availability
  } = req.body;

  if (!req.session.seller || !req.session.seller.id) {
    console.log('SESSION:', req.session);
    return res.status(401).send('Unauthorized: Please log in first');
  }




  const seller_id = req.session.seller.id;
  const image_url = req.file ? '/uploads/' + req.file.filename : '';

  try {
    await db.query(`
      INSERT INTO products 
      (name, price, stock, category, description, brand, color, size, currency, availability, seller_id, image_url)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    `, [
      name, price, stock, category,
      description, brand, color, size,
      currency, availability, seller_id, image_url
    ]);

    res.redirect('/seller/dashboard');
  } catch (err) {
    console.error('Error adding product:', err);
    res.status(500).send('Error listing product');
  }
});

app.get('/seller/edit-product/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.query('SELECT * FROM products WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).send('Product not found');
    }
    res.render('edit_product', { product: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching product');
  }
});


app.post('/seller/edit-product/:id', upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, description, category, price, stock, color, size, availability } = req.body;
  const image_url = req.file ? '/uploads/' + req.file.filename : null;

  try {
    if (image_url) {
      // ✅ Update all fields + new image
      await db.query(
        `UPDATE products 
         SET name=$1, description=$2, category=$3, price=$4, stock=$5, 
             color=$6, size=$7, availability=$8, image_url=$9
         WHERE id=$10`,
        [name, description, category, price, stock, color, size, availability, image_url, id]
      );
    } else {
      // ✅ Update all fields EXCEPT image
      await db.query(
        `UPDATE products 
         SET name=$1, description=$2, category=$3, price=$4, stock=$5, 
             color=$6, size=$7, availability=$8
         WHERE id=$9`,
        [name, description, category, price, stock, color, size, availability, id]
      );
    }

    res.redirect('/seller/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Error updating product');
  }
});


app.post('/seller/delete-product/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM products WHERE id=$1', [id]);
    res.redirect('/seller/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting product');
  }
});




// GET All Products by Seller
app.get('/seller/products', sellerAuth, async (req, res) => {
  const result = await db.query(
    `SELECT * FROM products WHERE seller_id=$1`,
    [req.session.seller.id]
  );
  res.render('products', { products: result.rows });
});

app.post('/fake-payment', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;

  // Here you would normally verify payment with Razorpay or Stripe
  // But we just mark it as PAID for demo purposes

  try {
    await db.query(
      `INSERT INTO orders (user_id, total_amount, payment_method, status)
       VALUES ($1, $2, $3, $4)`,
      [userId, 999, 'Dummy Payment', 'Paid']
    );

    res.render('order_success', { message: '🎉 Dummy payment successful! Your order has been placed.' });
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Error placing order');
  }
});


app.post('/start-payment', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login'); // ✅ Ensure user is logged in
  }

  const { product_id, quantity } = req.body;

  try {
    const productResult = await db.query('SELECT * FROM products WHERE id = $1', [product_id]);

    if (productResult.rows.length === 0) {
      return res.status(404).send('❌ Product not found');
    }

    const product = productResult.rows[0];

    // ✅ Render fake payment page
    res.render('payment_page', { product, quantity });
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Error starting payment');
  }
});


app.post('/process-payment', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;
  const { product_id, quantity, payment_status } = req.body;

  try {
    const productResult = await db.query('SELECT * FROM products WHERE id = $1', [product_id]);

    if (productResult.rows.length === 0) {
      return res.status(404).send('❌ Product not found');
    }

    const product = productResult.rows[0];

    // ✅ Only store order if payment was successful
    if (payment_status === 'success') {
      await db.query(
        `INSERT INTO orders (user_id, product_id, quantity, total_price, payment_method, status)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [userId, product.id, quantity, product.price * quantity, 'Fake Payment', 'Paid']
      );

      return res.render('order_success', { product, quantity });
    }

    // ❌ Payment failed → Show failure page
    res.render('order_failed', { product });
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Error processing payment');
  }
});

app.post('/checkout-payment', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login'); // ✅ Only logged-in users can pay
  }

  const userId = req.session.user.id;

  try {
    // ✅ Fetch all items from the user’s cart
    const cartItemsResult = await db.query(`
      SELECT c.product_id, p.name, p.price, p.image_url, c.quantity
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = $1
    `, [userId]);

    const cartItems = cartItemsResult.rows;

    if (cartItems.length === 0) {
      return res.send('❌ Your cart is empty!');
    }

    // ✅ Calculate total price
    let total = 0;
    cartItems.forEach(item => {
      total += item.price * item.quantity;
    });

    // ✅ Render the payment page
    res.render('cart_payment_page', { cartItems, total });
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Error loading checkout page');
  }
});

app.post('/process-cart-payment', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;
  const { payment_status } = req.body;

  try {
    // ✅ Fetch all cart items again (so we know what to insert into orders)
    const cartItemsResult = await db.query(`
      SELECT c.product_id, p.price, c.quantity
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = $1
    `, [userId]);

    const cartItems = cartItemsResult.rows;

    if (payment_status === 'success') {
      // ✅ Store each item as an order
      for (let item of cartItems) {
        await db.query(
          `INSERT INTO orders (user_id, product_id, quantity, total_price, payment_method, status)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [userId, item.product_id, item.quantity, item.price * item.quantity, 'Fake Payment', 'Paid']
        );
      }

      // ✅ Clear cart after payment
      await db.query('DELETE FROM cart_items WHERE user_id = $1', [userId]);

      return res.render('order_success', { product: null, quantity: null, cart: true });
    }

    // ❌ Payment failed – don’t store anything
    res.render('order_failed', { cart: true });
  } catch (err) {
    console.error(err);
    res.status(500).send('❌ Error processing cart payment');
  }
});

app.get('/seller/forgot-password', (req, res) => {
  res.render('seller_forgot_password'); // create this EJS page
});

app.post('/seller/forgot-password', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  const result = await db.query('SELECT * FROM sellers WHERE email = $1', [email]);
  if (result.rows.length === 0) {
    return res.send('Seller not found.');
  }

  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 }; // expires in 5 mins

  // Send OTP
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your Seller OTP',
    html: `<p>Your OTP is: <b>${otp}</b>. It expires in 5 minutes.</p>`
  });

  res.render('seller_enter_otp', { email });
});


app.post('/seller/reset-password', async (req, res) => {
  const { email, otp, new_password } = req.body;
  const record = otpStore[email];

  if (!record || record.otp !== otp || Date.now() > record.expires) {
    return res.send('Invalid or expired OTP.');
  }

  const hashed = await bcrypt.hash(new_password, 10);
  await db.query('UPDATE sellers SET password = $1 WHERE email = $2', [hashed, email]);

  delete otpStore[email];

  res.send('✅ Password reset successfully. You can now <a href="/seller/login">login</a>.');
});




app.listen(port, (req, res) => {
  console.log(`Server is running in port ${port}`)
})