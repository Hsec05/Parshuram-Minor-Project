// SOC/util/redisBroker.js
require('dotenv').config();
const { createClient } = require('@redis/client');

const redisBrokerClient = createClient({
  socket: {
    host: process.env.REDIS_BROKER_HOST,
    port: process.env.REDIS_BROKER_PORT
  }
});

redisBrokerClient.on('error', (err) => console.error('Redis Broker Client Error', err));

(async () => {
  await redisBrokerClient.connect();
  console.log('Connected to Redis Broker');
})();

module.exports = redisBrokerClient;