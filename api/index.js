const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User.js');
const Place = require('./models/Place.js');
const Booking = require('./models/Booking.js');
const cookieParser = require('cookie-parser');
const imageDownloader = require('image-downloader');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const multer = require('multer');
const fs = require('fs');
const mime = require('mime-types');

require('dotenv').config();
const app = express();

const bcryptSalt = bcrypt.genSaltSync(10);
const jwtSecret = 'fasefraw4r5r3wq45wdfgw34twdfg';
const bucket = 'sanchay-booking-app';

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));

// CORS setup to allow requests from frontend (http://localhost:5173)
app.use(cors({
  credentials: true,const express = require('express');
  const cors = require('cors');
  const mongoose = require("mongoose");
  const bcrypt = require('bcryptjs');
  const jwt = require('jsonwebtoken');
  const User = require('./models/User.js');
  const Place = require('./models/Place.js');
  const Booking = require('./models/Booking.js');
  const cookieParser = require('cookie-parser');
  const imageDownloader = require('image-downloader');
  const {S3Client, PutObjectCommand} = require('@aws-sdk/client-s3');
  const multer = require('multer');
  const fs = require('fs');
  const mime = require('mime-types');
  
  require('dotenv').config();
  const app = express();
  
  const bcryptSalt = bcrypt.genSaltSync(10);
  const jwtSecret = 'fasefraw4r5r3wq45wdfgw34twdfg';
  const bucket = 'sanchay-booking-app';
  
  app.use(express.json());
  app.use(cookieParser());
  app.use('/uploads', express.static(__dirname+'/uploads'));
  app.use(cors({
    credentials: true,
    origin: 'https://booking-bh130qo5x-sanchays-projects-03b646fc.vercel.app/',
  }));
  
  async function uploadToS3(path, originalFilename, mimetype) {
    const client = new S3Client({
      region: 'eu-north-1',
      credentials: {
        accessKeyId: process.env.S3_ACCESS_KEY,
        secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
      },
    });
    const parts = originalFilename.split('.');
    const ext = parts[parts.length - 1];
    const newFilename = Date.now() + '.' + ext;
    await client.send(new PutObjectCommand({
      Bucket: bucket,
      Body: fs.readFileSync(path),
      Key: newFilename,
      ContentType: mimetype,
      ACL: 'public-read',
    }));
    return `https://${bucket}.s3.amazonaws.com/${newFilename}`;
  }
  
  function getUserDataFromReq(req) {
    return new Promise((resolve, reject) => {
      jwt.verify(req.cookies.token, jwtSecret, {}, async (err, userData) => {
        if (err) throw err;
        resolve(userData);
      });
    });
  }
  
  app.get('/api/test', (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    res.json('test ok');
  });
  
  app.post('/api/register', async (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const {name,email,password} = req.body;
  
    try {
      const userDoc = await User.create({
        name,
        email,
        password:bcrypt.hashSync(password, bcryptSalt),
      });
      res.json(userDoc);
    } catch (e) {
      res.status(422).json(e);
    }
  
  });
  
  app.post('/api/login', async (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const {email,password} = req.body;
    const userDoc = await User.findOne({email});
    if (userDoc) {
      const passOk = bcrypt.compareSync(password, userDoc.password);
      if (passOk) {
        jwt.sign({
          email:userDoc.email,
          id:userDoc._id
        }, jwtSecret, {}, (err,token) => {
          if (err) throw err;
          res.cookie('token', token).json(userDoc);
        });
      } else {
        res.status(422).json('pass not ok');
      }
    } else {
      res.json('not found');
    }
  });
  
  app.get('/api/profile', (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const {token} = req.cookies;
    if (token) {
      jwt.verify(token, jwtSecret, {}, async (err, userData) => {
        if (err) throw err;
        const {name,email,_id} = await User.findById(userData.id);
        res.json({name,email,_id});
      });
    } else {
      res.json(null);
    }
  });
  
  app.post('/api/logout', (req,res) => {
    res.cookie('token', '').json(true);
  });
  
  
  app.post('/api/upload-by-link', async (req,res) => {
    const {link} = req.body;
    const newName = 'photo' + Date.now() + '.jpg';
    await imageDownloader.image({
      url: link,
      dest: '/tmp/' +newName,
    });
    const url = await uploadToS3('/tmp/' +newName, newName, mime.lookup('/tmp/' +newName));
    res.json(url);
  });
  
  const photosMiddleware = multer({dest:'/tmp'});
  app.post('/api/upload', photosMiddleware.array('photos', 100), async (req,res) => {
    const uploadedFiles = [];
    for (let i = 0; i < req.files.length; i++) {
      const {path,originalname,mimetype} = req.files[i];
      const url = await uploadToS3(path, originalname, mimetype);
      uploadedFiles.push(url);
    }
    res.json(uploadedFiles);
  });
  
  app.post('/api/places', (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const {token} = req.cookies;
    const {
      title,address,addedPhotos,description,price,
      perks,extraInfo,checkIn,checkOut,maxGuests,
    } = req.body;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      if (err) throw err;
      const placeDoc = await Place.create({
        owner:userData.id,price,
        title,address,photos:addedPhotos,description,
        perks,extraInfo,checkIn,checkOut,maxGuests,
      });
      res.json(placeDoc);
    });
  });
  
  app.get('/api/user-places', (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const {token} = req.cookies;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      const {id} = userData;
      res.json( await Place.find({owner:id}) );
    });
  });
  
  app.get('/api/places/:id', async (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const {id} = req.params;
    res.json(await Place.findById(id));
  });
  
  app.put('/api/places', async (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const {token} = req.cookies;
    const {
      id, title,address,addedPhotos,description,
      perks,extraInfo,checkIn,checkOut,maxGuests,price,
    } = req.body;
    jwt.verify(token, jwtSecret, {}, async (err, userData) => {
      if (err) throw err;
      const placeDoc = await Place.findById(id);
      if (userData.id === placeDoc.owner.toString()) {
        placeDoc.set({
          title,address,photos:addedPhotos,description,
          perks,extraInfo,checkIn,checkOut,maxGuests,price,
        });
        await placeDoc.save();
        res.json('ok');
      }
    });
  });
  
  app.get('/api/places', async (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    res.json( await Place.find() );
  });
  
  app.post('/api/bookings', async (req, res) => {
    mongoose.connect(process.env.MONGO_URL);
    const userData = await getUserDataFromReq(req);
    const {
      place,checkIn,checkOut,numberOfGuests,name,phone,price,
    } = req.body;
    Booking.create({
      place,checkIn,checkOut,numberOfGuests,name,phone,price,
      user:userData.id,
    }).then((doc) => {
      res.json(doc);
    }).catch((err) => {
      throw err;
    });
  });
  
  
  
  app.get('/api/bookings', async (req,res) => {
    mongoose.connect(process.env.MONGO_URL);
    const userData = await getUserDataFromReq(req);
    res.json( await Booking.find({user:userData.id}).populate('place') );
  });
  app.listen(process.env.PORT);
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],  // Allowing multiple origins if needed
}));

// Connect to MongoDB once at the start of the app
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log("MongoDB connected");
}).catch((err) => {
  console.error("MongoDB connection error:", err);
});

// Helper function to upload files to S3
async function uploadToS3(path, originalFilename, mimetype) {
  const client = new S3Client({
    region: 'eu-north-1',
    credentials: {
      accessKeyId: process.env.S3_ACCESS_KEY,
      secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
    },
  });
  const parts = originalFilename.split('.');
  const ext = parts[parts.length - 1];
  const newFilename = Date.now() + '.' + ext;
  await client.send(new PutObjectCommand({
    Bucket: bucket,
    Body: fs.readFileSync(path),
    Key: newFilename,
    ContentType: mimetype,
    ACL: 'public-read',
  }));
  return `https://${bucket}.s3.amazonaws.com/${newFilename}`;
}

// Helper function to get user data from the JWT token
function getUserDataFromReq(req) {
  return new Promise((resolve, reject) => {
    jwt.verify(req.cookies.token, jwtSecret, {}, async (err, userData) => {
      if (err) return reject(err);
      resolve(userData);
    });
  });
}

// Test route to check if the server is working
app.get('/api/test', (req, res) => {
  res.json('test ok');
});

// Register route to create a new user
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    const userDoc = await User.create({
      name,
      email,
      password: hashedPassword,
    });
    res.json(userDoc);
  } catch (e) {
    console.error("Error during registration:", e);
    res.status(422).json(e);
  }
});

// Login route to authenticate a user
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userDoc = await User.findOne({ email });
    if (userDoc) {
      const passOk = bcrypt.compareSync(password, userDoc.password);
      if (passOk) {
        jwt.sign({ email: userDoc.email, id: userDoc._id }, jwtSecret, {}, (err, token) => {
          if (err) throw err;
          res.cookie('token', token).json(userDoc);
        });
      } else {
        res.status(422).json('Password incorrect');
      }
    } else {
      res.status(404).json('User not found');
    }
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

// Profile route to get logged-in user details
app.get('/api/profile', async (req, res) => {
  const { token } = req.cookies;
  if (token) {
    try {
      const userData = await getUserDataFromReq(req);
      const { name, email, _id } = await User.findById(userData.id);
      res.json({ name, email, _id });
    } catch (err) {
      console.error("Profile error:", err);
      res.status(500).json({ message: "Server error" });
    }
  } else {
    res.json(null);
  }
});

// Logout route to clear the user's session
app.post('/api/logout', (req, res) => {
  res.cookie('token', '').json(true);
});

// File upload via URL link
app.post('/api/upload-by-link', async (req, res) => {
  const { link } = req.body;
  const newName = 'photo' + Date.now() + '.jpg';
  try {
    await imageDownloader.image({ url: link, dest: '/tmp/' + newName });
    const url = await uploadToS3('/tmp/' + newName, newName, mime.lookup('/tmp/' + newName));
    res.json(url);
  } catch (err) {
    console.error("File upload by link error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Middleware to handle file uploads
const photosMiddleware = multer({ dest: '/tmp' });
app.post('/api/upload', photosMiddleware.array('photos', 100), async (req, res) => {
  const uploadedFiles = [];
  for (let i = 0; i < req.files.length; i++) {
    const { path, originalname, mimetype } = req.files[i];
    try {
      const url = await uploadToS3(path, originalname, mimetype);
      uploadedFiles.push(url);
    } catch (err) {
      console.error("File upload error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
  res.json(uploadedFiles);
});

// Create a new place (requires user to be logged in)
app.post('/api/places', async (req, res) => {
  const { token } = req.cookies;
  const {
    title, address, addedPhotos, description, price,
    perks, extraInfo, checkIn, checkOut, maxGuests,
  } = req.body;
  try {
    const userData = await getUserDataFromReq(req);
    const placeDoc = await Place.create({
      owner: userData.id,
      title, address, photos: addedPhotos, description,
      price, perks, extraInfo, checkIn, checkOut, maxGuests,
    });
    res.json(placeDoc);
  } catch (err) {
    console.error("Create place error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all places owned by the logged-in user
app.get('/api/user-places', async (req, res) => {
  try {
    const userData = await getUserDataFromReq(req);
    const places = await Place.find({ owner: userData.id });
    res.json(places);
  } catch (err) {
    console.error("Error fetching user places:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get place by ID
app.get('/api/places/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const place = await Place.findById(id);
    res.json(place);
  } catch (err) {
    console.error("Error fetching place:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Update a place (only for the owner)
app.put('/api/places', async (req, res) => {
  const { token } = req.cookies;
  const {
    id, title, address, addedPhotos, description,
    perks, extraInfo, checkIn, checkOut, maxGuests, price,
  } = req.body;
  try {
    const userData = await getUserDataFromReq(req);
    const placeDoc = await Place.findById(id);
    if (userData.id === placeDoc.owner.toString()) {
      placeDoc.set({
        title, address, photos: addedPhotos, description,
        perks, extraInfo, checkIn, checkOut, maxGuests, price,
      });
      await placeDoc.save();
      res.json('ok');
    } else {
      res.status(403).json({ message: "You are not the owner of this place" });
    }
  } catch (err) {
    console.error("Error updating place:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all places (public route)
app.get('/api/places', async (req, res) => {
  try {
    const places = await Place.find();
    res.json(places);
  } catch (err) {
    console.error("Error fetching places:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Create a new booking
app.post('/api/bookings', async (req, res) => {
  try {
      const userData = await getUserDataFromReq(req);
      const {
          place, checkIn, checkOut, numberOfGuests, name, phone, price, paymentIntentId,
      } = req.body;

      const booking = await Booking.create({
          place,
          checkIn,
          checkOut,
          numberOfGuests,
          name,
          phone,
          price,
          paymentIntentId,
          user: userData.id,
      });

      res.json(booking);
  } catch (err) {
      console.error("Error creating booking:", err);
      res.status(500).json({message: "Server error"});
  }
});



// Get all bookings for the logged-in user
app.get('/api/bookings', async (req, res) => {
  try {
    const userData = await getUserDataFromReq(req);
    const bookings = await Booking.find({ user: userData.id }).populate('place');
    res.json(bookings);
  } catch (err) {
    console.error("Error fetching bookings:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post('/create-payment-intent', async (req, res) => {
  const {amount} = req.body; // Amount in the smallest currency unit (paise)
  try {
      const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: 'inr',
          payment_method_types: ['card'],
      });
      res.status(200).json({clientSecret: paymentIntent.client_secret});
  } catch (error) {
      console.error("Stripe error:", error.message);
      res.status(500).json({error: error.message});
  }
});

app.get('/bookings/:id', async (req, res) => {
  const bookingId = req.params.id;
  const booking = await Booking.findById(bookingId); // Replace with your actual database query
  if (booking) {
    res.json(booking);
  } else {
    res.status(404).send('Booking not found');
  }
});



// Start the server
app.listen(PORT, () => {
  console.log('Server is running on http://localhost:4000');
});
