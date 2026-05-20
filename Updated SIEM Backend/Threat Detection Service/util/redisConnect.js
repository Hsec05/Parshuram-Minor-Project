require('dotenv').config();
const { createClient } = require('@redis/client');

const redisClient = createClient({
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT
  }
});

redisClient.on('error', (err) => console.error('Redis Client Error', err));

(async () => {
  await redisClient.connect();
  console.log('Connected to Redis');
})();

module.exports = redisClient;

//to start new container: docker run --name redis -p 6379:6379 -d redis
// to start old container: docker start redis