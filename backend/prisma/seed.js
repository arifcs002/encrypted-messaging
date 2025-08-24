const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

require('dotenv').config();

async function main() {
  const client = new MongoClient(process.env.DATABASE_URL);
  
  try {
    await client.connect();
    const db = client.db();
    const usersCollection = db.collection('users');
    
    // Check if admin exists
    const adminExists = await usersCollection.findOne({ email: 'admin@example.com' });
    
    if (!adminExists) {
      const hashedPassword = bcrypt.hashSync('admin123', 8);
      await usersCollection.insertOne({
        username: 'admin',
        email: 'admin@example.com',
        password: hashedPassword,
        role: 'ADMIN',
        isBlocked: false,
        forcedPasswordReset: false,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      console.log('Admin user created');
    }
    
    // Check if regular user exists
    const userExists = await usersCollection.findOne({ email: 'user1@example.com' });
    
    if (!userExists) {
      const userPassword = bcrypt.hashSync('password', 8);
      await usersCollection.insertOne({
        username: 'user1',
        email: 'user1@example.com',
        password: userPassword,
        role: 'USER',
        isBlocked: false,
        forcedPasswordReset: false,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      console.log('Regular user created');
    }
    
    console.log('Database seeded successfully');
  } catch (error) {
    console.error('Error seeding database:', error);
  } finally {
    await client.close();
  }
}

main();