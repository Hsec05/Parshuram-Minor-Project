const mongoose = require('mongoose');
// const Agent = require('./models/agent');

// mongoose.connect('mongodb://localhost:27017/your_db', { useNewUrlParser: true, useUnifiedTopology: true })
// .then(async () => {
//   const count = await Agent.countDocuments({ active: true });
//   console.log('Active agents:', count);
//   process.exit();
// })
// .catch(err => {
//   console.error(err);
//   process.exit(1);
// });
const Agent = require('./models/agent');

async function test() {
  await mongoose.connect('mongodb://localhost:27017/Parshuram2');
  const count = await Agent.countDocuments({ active: true });
  console.log('Active agents:', count);
  process.exit();
}

test();