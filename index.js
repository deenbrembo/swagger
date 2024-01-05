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
const { v4: uuidv4 } = require('uuid');
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
 * /loginHost:
 *   post:
 *     summary: Authenticate Host
 *     description: Login for Host
 *     tags:
 *       - Host
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
  app.post('/loginhost', async (req, res) => {
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
 *       - Admin
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
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *               - name
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
 * /registerHost:
 *   post:
 *     summary: Register a new host
 *     description: Register a new host with required details
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
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - username
 *               - password
 *               - name
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Host registration successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.post('/registerHost', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  
  /**
 * @swagger
 * /readVisitor:
 *   get:
 *     summary: Read host and visitor information
 *     description: Retrieve information for a host and visitor
 *     tags:
 *       - Host
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
 * /issuePass:
 *   post:
 *     summary: Issue visitor pass by Host
 *     description: Issue a visitor pass and add visitor information to Records
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newName:
 *                 type: string
 *               newPhoneNumber:
 *                 type: string
 *             required:
 *               - newName
 *               - newPhoneNumber
 *     responses:
 *       '200':
 *         description: Visitor pass issued successfully. PassIdentifier generated for the pass.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Visitor pass issued successfully. PassIdentifier: abc123"
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.post('/issuePass', verifyToken, async (req, res) => {
    try {
      const data = req.user;
  
      if (data.role !== 'Host') {
        return res.status(401).send('Unauthorized - Host access only');
      }
  
      const { newName, newPhoneNumber } = req.body;
  
      // Generate a unique PassIdentifier (e.g., using UUID or any unique identifier method)
      const passIdentifier = generatePassIdentifier(); // You need to implement this function
  
      const result = await client.db('assigment').collection('Records').insertOne({
        name: newName,
        phoneNumber: newPhoneNumber,
        hostUsername: data.username,
        issueDate: new Date(),
        passIdentifier: passIdentifier, // Include the PassIdentifier in the record
      });
  
      if (result.insertedCount === 1) {
        return res.status(200).send('Visitor pass issued successfully. PassIdentifier: ' + passIdentifier);
      } else {
        return res.status(500).send('Failed to issue visitor pass');
      }
    } catch (error) {
      console.error(error);
      return res.status(500).send('Internal Server Error');
    }
  });
  
 
  /**
 * @swagger
 * /retrievePass:
 *   get:
 *     summary: Retrieve visitor pass by PassIdentifier
 *     description: Retrieve a visitor pass using the PassIdentifier
 *     tags:
 *       - Visitor
 *     parameters:
 *       - in: query
 *         name: passIdentifier
 *         required: true
 *         description: PassIdentifier for the visitor's pass
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Visitor pass retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/VisitorPass'
 *       '404':
 *         description: PassIdentifier not found or invalid
 */
app.get('/retrievePass', async (req, res) => {
  try {
    const passIdentifier = req.query.passIdentifier;

    // Search for the pass using the provided PassIdentifier
    const pass = await client.db('assigment').collection('Records').findOne({ passIdentifier });

    if (!pass) {
      return res.status(404).send('PassIdentifier not found or invalid');
    }

    // Return the pass information if found
    return res.status(200).json(pass);
  } catch (error) {
    console.error(error);
    return res.status(500).send('Internal Server Error');
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


//Function to login
async function login(client, data) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const hostCollection = client.db("assigment").collection("Host");

  // Find the admin user
  let match = await adminCollection.findOne({ username: data.username });

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }

  if (!match) {
    // Find the host user
    match = await hostCollection.findOne({ username: data.username });
  }

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);


    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);

      switch (match.role) {
        case "Admin":
          return "You are logged in as Admin\n1) Register Security\n2) Dumb All host Data\n\nToken for " + match.name + ": " + token + "\n";
        case "Security":
          return "You are logged in as Security\n1) register Host\n\nToken for " + match.name + ": " + token + "\n";
        case "Host":
          return "You are logged in as a Host User\n1) Issue the Pass for Visitor\n\nToken for " + match.name + ": " + token + "\n";
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
  const securityCollection = client.db("assigment").collection("Security");
  const hostCollection = client.db("assigment").collection("Host");

  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempUser = await hostCollection.findOne({ username: mydata.username });

  if (tempSecurity || tempUser) {
    return "Username already in use, please enter another username";
  }

  if (data.role === "Admin") {
    const result = await securityCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      phoneNumber: mydata.phoneNumber,
      role: "Security",
      host: [],
    });

    return "Security registered successfully";
  }

  if (data.role === "Security") {
    const result = await hostCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      Security: data.username,
      phoneNumber: mydata.phoneNumber,
      role: "Host",
      records: [],
    });

    const updateResult = await securityCollection.updateOne(
      { username: data.username },
      { $push: { host: mydata.username } }
    );

    return "Host registered successfully";
  }
}



//Function to read data
async function read(client, data) {

  if (data.role == 'Host') {
    const Host = await client.db('assigment').collection('Host').findOne({ username: data.username });
    if (!Host) {
      return 'User not found';
    }
    const Records = await client.db('assigment').collection('Records').find({ recordID: { $in: Host.records } }).toArray();

    return { Host, Records };
  }
}


//Function to delete data
async function deleteUser(client, data) {
  const hostCollection = client.db("assigment").collection("Users");
  const recordsCollection = client.db("assigment").collection("Records");
  const securityCollection = client.db("assigment").collection("Security");

  // Delete user document
  const deleteResult = await hostCollection.deleteOne({ username: data.username });
  if (deleteResult.deletedCount === 0) {
    return "User not found";
  }

  // Update visitors array in other users' documents
  await hostCollection.updateMany(
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

function generatePassIdentifier() {
  return uuidv4(); // Generates a UUID (e.g., '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed')
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


