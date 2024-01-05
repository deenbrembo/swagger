const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'VMS API',
            version: '1.0.0'
        },
        components: {  // Add 'components' section
            securitySchemes: {  // Define 'securitySchemes'
                bearerAuth: {  // Define 'bearerAuth'
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
const saltRounds = 10;
const uri = "mongodb+srv://deenbrembo:hafizudin202@cluster0.vlncwtu.mongodb.net/";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});


async function run() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  console.log("You successfully connected to MongoDB!");

  app.use(express.json());
  app.listen(port, () => {
    console.log(`Server listening at http://localSecurity:${port}`);
  });

  app.get('/', (req, res) => {
    res.send('Welcome to the Security Management System');
  });

  
  /**
 * @swagger
 * /registerAdmin:
 *   post:
 *     summary: Register a new admin
 *     description: Register a new admin user with required details
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [Admin]
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *               - role
 *     responses:
 *       '200':
 *         description: Admin registration successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 */
  app.post('/registerAdmin', async (req, res) => {
    let data = req.body;
    res.send(await registerAdmin(client, data));
  });

  /**
 * @swagger
 * /loginAdmin:
 *   post:
 *     summary: Authenticate admin
 *     description: Login with admin credentials
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Admin login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginAdmin', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

  /**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: Authenticate security personnel
 *     description: Login with security personnel credentials
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Security personnel login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginSecurity', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

   /**
 * @swagger
 * /Issue Visitor Pass:
 *   post:
 *     summary: Issue the visitor(give a security Token) for Visitor Pass(Token from visitor)
 *     description: Login with security personnel credentials
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Security personnel login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
   app.post('/IssueVisitorPass', async (req, res) => {
    let data = req.body;
    res.send(await issuethepass(client, data));
  });

  /**
 * @swagger
 * /Retrieve Visitor Pass:
 *   post:
 *     summary: Give the 
 *     description: Login for visitors
 *     tags:
 *       - Visitor
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '500':
 *         description: Visitor login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
  app.post('/loginVisitor', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data));
  });

  /**
 * @swagger
 * /registerSecurity:
 *   post:
 *     summary: Register a new security personnel
 *     description: Register a new security personnel with required details
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Security personnel registration successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.post('/registerSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  
  /**
 * @swagger
 * /registerVisitor:
 *   post:
 *     summary: Register a new visitor
 *     description: Register a new visitor with required details
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               icNumber:
 *                 type: string
 *               company:
 *                 type: string
 *               vehicleNumber:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *               - name
 *               - icNumber
 *               - company
 *               - vehicleNumber
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Visitor registration successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.post('/registerVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  /**
 * @swagger
 * /readAdmin:
 *   get:
 *     summary: Read admin information
 *     description: Retrieve information for an admin user
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '500':
 *         description: Admin information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AdminInfo'
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.get('/readAdmin', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  
  /**
 * @swagger
 * /readSecurity:
 *   get:
 *     summary: Read security personnel information
 *     description: Retrieve information for security personnel
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '500':
 *         description: Security personnel information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SecurityInfo'
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.get('/readSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  
  /**
 * @swagger
 * /readVisitor:
 *   get:
 *     summary: Read visitor information
 *     description: Retrieve information for a visitor
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '500':
 *         description: Visitor information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/VisitorInfo'
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.get('/readVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  

 
  /**
 * @swagger
 * /updateVisitor:
 *   patch:
 *     summary: Update visitor information
 *     description: Update information for a visitor
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               icNumber:
 *                 type: string
 *               company:
 *                 type: string
 *               vehicleNumber:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - password
 *               - name
 *               - icNumber
 *               - company
 *               - vehicleNumber
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Visitor information updated successfully
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.patch('/updateVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await update(client, data, mydata));
  });

  /**
 * @swagger
 * /deleteVisitor:
 *   delete:
 *     summary: Delete visitor account
 *     description: Delete a visitor's account
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Visitor account deleted successfully
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.delete('/deleteVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await deleteUser(client, data));
  });


 
  /**
 * @swagger
 * /checkIn (Retrive Visitor Pass):
 *   post:
 *     summary: Retrive Visitor Pass from Security TO check in
 *     description: Perform check-in for a visitor with record ID and purpose by security personnel
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []  // Assuming security personnel token required
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               recordID:
 *                 oneOf:
 *                   - type: string
 *                   - type: integer
 *               purpose:
 *                 type: string
 *             required:
 *               - recordID
 *               - purpose
 *     responses:
 *       '200':
 *         description: Check-in successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Security token is missing or invalid
 */
  app.post('/checkIn', verifyToken, async (req, res) => {
    try {
      const data = req.user; // Assuming the user's role is Visitor
      const mydata = req.body;
      const securityToken = req.headers.authorization; // Extract security token from header
  
      const checkInResponse = await checkInBySecurity(client, securityToken, data.username, mydata.recordID, mydata.purpose);
      res.send(checkInResponse);
    } catch (error) {
      console.error(error);
      res.status(500).send('Error during check-in');
    }
  });


/**
 * @swagger
 * /checkOut (Retrieve Visitor Pass):
 *   post:
 *     summary: Retrieve Visitor Pass from Security TO check out
 *     description: Update check-out time for a visitor by security personnel
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []  // Assuming security personnel token required
 *     responses:
 *       '200':
 *         description: Check-out successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Security token is missing or invalid
 */
app.post('/checkOut', verifyToken, async (req, res) => {
  try {
    const data = req.user; // Assuming the user's role is Visitor
    const securityToken = req.headers.authorization; // Extract security token from header

    const checkOutResponse = await checkOutBySecurity(client, securityToken, data.username);
    res.send(checkOutResponse);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error during check-out');
  }
});
}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'dinpassword',           //password
  { expiresIn: '2h' });  //expires after 2 hour
}

//Function to register admin
async function registerAdmin(client, data) {
  data.password = await encryptPassword(data.password);
  
  const existingUser = await client.db("swagger").collection("Admin").findOne({ username: data.username });
  if (existingUser) {
    return 'Username already registered';
  } else {
    const result = await client.db("swagger").collection("Admin").insertOne(data);
    return 'Admin registered';
  }
}


//Function to login
async function login(client, data) {
  const adminCollection = client.db("swagger").collection("Admin");
  const securityCollection = client.db("swagger").collection("Security");
  const usersCollection = client.db("swagger").collection("Users");

  // Find the admin user
  let match = await adminCollection.findOne({ username: data.username });

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }

  if (!match) {
    // Find the regular user
    match = await usersCollection.findOne({ username: data.username });
  }

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);


    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);

      switch (match.role) {
        case "Admin":
          return "You are logged in as Admin\n1) Register Security\n2) Read all data\n\nToken for " + match.name + ": " + token + "\n";
        case "Security":
          return "You are logged in as Security\n1) register Visitor\n2) read security and visitor data\n3) Issue Visitor Pass\n\nToken for " + match.name + ": " + token + "\n";
        case "Visitor":
          return "You are logged in as a regular visitor User\n1) check in\n2) check out\n3) read visitor data\n4) update profile\n5) delete account\n\nToken for " + match.name + ": " + token + "\n";
        default:
          return "Role not defined";
      }
    }
     else {
      return "Wrong password";
    }
  } else {
    return "User not found";
  }
}

async function issuethepass(client, data) {

  const securityCollection = client.db("swagger").collection("Security");

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }


  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);


    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);

      switch (match.role) {
        case "Security":
          return "Pass from " + match.name + ": " + token + "\n";
        default:
          return "Role not defined";
      }
    }
     else {
      return "Wrong password";
    }
  } else {
    return "User not found";
  }
}



//Function to encrypt password
async function encryptPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds); 
  return hash 
}


//Function to decrypt password
async function decryptPassword(password, compare) {
  const match = await bcrypt.compare(password, compare)
  return match
}


//Function to register security and visitor
async function register(client, data, mydata) {
  const adminCollection = client.db("swagger").collection("Admin");
  const securityCollection = client.db("swagger").collection("Security");
  const usersCollection = client.db("swagger").collection("Users");

  const tempAdmin = await adminCollection.findOne({ username: mydata.username });
  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempUser = await usersCollection.findOne({ username: mydata.username });

  if (tempAdmin || tempSecurity || tempUser) {
    return "Username already in use, please enter another username";
  }

  if (data.role === "Admin") {
    const result = await securityCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      phoneNumber: mydata.phoneNumber,
      role: "Security",
      visitors: [],
    });

    return "Security registered successfully";
  }

  if (data.role === "Security") {
    const result = await usersCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      
      Security: data.username,
      company: mydata.company,
      vehicleNumber: mydata.vehicleNumber,
      icNumber: mydata.icNumber,
      phoneNumber: mydata.phoneNumber,
      role: "Visitor",
      records: [],
    });

    const updateResult = await securityCollection.updateOne(
      { username: data.username },
      { $push: { visitors: mydata.username } }
    );

    return "Visitor registered successfully";
  }
}





//Function to read data
async function read(client, data) {
  if (data.role == 'Admin') {
    const Admins = await client.db('swagger').collection('Admin').find({ role: 'Admin' }).next();
    const Securitys = await client.db('swagger').collection('Security').find({ role: 'Security' }).toArray();
    const Visitors = await client.db('swagger').collection('Users').find({ role: 'Visitor' }).toArray();
    const Records = await client.db('swagger').collection('Records').find().toArray();

    return { Admins, Securitys, Visitors, Records };
  }

  if (data.role == 'Security' ) {
    const Security = await client.db('swagger').collection('Security').findOne({ username: data.username });
    if (!Security) {
      return 'User not found';
    }

    const Visitors = await client.db('swagger').collection('Users').find({ Security: data.username }).toArray();
    const Records = await client.db('swagger').collection('Records').find().toArray();

    return { Security, Visitors, Records };
  }

  if (data.role == 'Visitor') {
    const Visitor = await client.db('swagger').collection('Users').findOne({ username: data.username });
    if (!Visitor) {
      return 'User not found';
    }

    const Records = await client.db('swagger').collection('Records').find({ recordID: { $in: Visitor.records } }).toArray();

    return { Visitor, Records };
  }
}


//Function to update data
async function update(client, data, mydata) {
  const usersCollection = client.db("swagger").collection("Users");

  if (mydata.password) {
    mydata.password = await encryptPassword(mydata.password);
  }

  const result = await usersCollection.updateOne(
    { username: data.username },
    { $set: mydata }
  );

  if (result.matchedCount === 0) {
    return "User not found";
  }

  return "Update Successfully";
}


//Function to delete data
async function deleteUser(client, data) {
  const usersCollection = client.db("swagger").collection("Users");
  const recordsCollection = client.db("swagger").collection("Records");
  const securityCollection = client.db("swagger").collection("Security");

  // Delete user document
  const deleteResult = await usersCollection.deleteOne({ username: data.username });
  if (deleteResult.deletedCount === 0) {
    return "User not found";
  }

  // Update visitors array in other users' documents
  await usersCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  // Update visitors array in the Security collection
  await securityCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  return "Delete Successful\nBut the records are still in the database";
}






// Function to handle check-in by security
async function checkInBySecurity(client, securityToken, visitorUsername, recordID, purpose) {
  try {
    const decodedSecurity = jwt.verify(securityToken, 'dinpassword');
    if (decodedSecurity.role !== 'Security') {
      return 'Unauthorized: Invalid security token';
    }

    // Check-in logic here
    const usersCollection = client.db('swagger').collection('Users');
    const recordsCollection = client.db('swagger').collection('Records');

    const visitor = await usersCollection.findOne({ username: visitorUsername });
    if (!visitor || visitor.role !== 'Visitor') {
      return 'Visitor not found or invalid';
    }

    if (visitor.currentCheckIn) {
      return 'Visitor is already checked in';
    }

    const existingRecord = await recordsCollection.findOne({ recordID });
    if (existingRecord) {
      return `Record ID '${recordID}' already exists, please choose another`;
    }

    const checkInTime = new Date();

    const recordData = {
      username: visitorUsername,
      recordID,
      purpose,
      checkInTime,
      securityPersonnel: decodedSecurity.username // Optionally record who checked the visitor in
    };

    await recordsCollection.insertOne(recordData);

    await usersCollection.updateOne(
      { username: visitorUsername },
      {
        $set: { currentCheckIn: recordID },
        $push: { records: recordID }
      }
    );

    return `Visitor '${visitorUsername}' checked in successfully at '${checkInTime}' with record ID '${recordID}'`;
  } catch (error) {
    console.error(error);
    return 'Error while processing check-in';
  }
}

// Function to handle check-out by security
async function checkOutBySecurity(client, securityToken, visitorUsername) {
  try {
    const decodedSecurity = jwt.verify(securityToken, 'dinpassword');
    if (decodedSecurity.role !== 'Security') {
      return 'Unauthorized: Invalid security token';
    }

    // Check-out logic here
    const usersCollection = client.db('swagger').collection('Users');
    const recordsCollection = client.db('swagger').collection('Records');

    const visitor = await usersCollection.findOne({ username: visitorUsername });
    if (!visitor || visitor.role !== 'Visitor') {
      return 'Visitor not found or invalid';
    }

    if (!visitor.currentCheckIn) {
      return 'Visitor is not checked in';
    }

    const checkOutTime = new Date();

    const updateResult = await recordsCollection.updateOne(
      { recordID: visitor.currentCheckIn },
      { $set: { checkOutTime } }
    );

    if (updateResult.modifiedCount === 0) {
      return 'Failed to update check-out time';
    }

    const unsetResult = await usersCollection.updateOne(
      { username: visitorUsername },
      { $unset: { currentCheckIn: 1 } }
    );

    if (unsetResult.modifiedCount === 0) {
      return 'Failed to check out';
    }

    return `Visitor '${visitorUsername}' checked out successfully at '${checkOutTime}'`;
  } catch (error) {
    console.error(error);
    return 'Error while processing check-out';
  }
}




//Function to output
function output(data) {
  if(data == 'Admin') {
    return "You are logged in as Admin\n1)register Security\n2)read all data"
  } else if (data == 'Security') {
    return "You are logged in as Security\n1)register Visitor\n2)read security and visitor data"
  } else if (data == 'Visitor') {
    return "You are logged in as Visitor\n1)check in\n2)check out\n3)read visitor data\n4)update profile\n5)delete account"
  }
}



//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'dinpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}


