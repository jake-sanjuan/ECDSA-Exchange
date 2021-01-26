const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const EC = require('elliptic').ec;
const SHA256 = require('crypto-js/sha256');

const ec = new EC('secp256k1');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const balances = {
  '04b53d2415e45d34882665797abe8aca9896d8bf81890013bf52290be89a0227cb6922f226cae02b1a487351308978894c0d1b09f112c059a2a80cfe8367865fba': 100,
  '04f78e3e1b75e0badd350e81ddc5f24d7a64c2b0cf524fc20068ca17eee0b1e21d2ca58c68deff1aa20f3c9b95eab4a9b1d45d4ee09434f3ebbaf3bcf5baff86fb': 50,
  '049d99dbe50b67b27462bea2f935a234b1b0493d7021c3c977d7cf9197c8a00d749270277bfa0eb327b7e3cdaf5c4b8b979c03d584dfd2a7f56e0cefb0381608ec': 75,
}

/**
const privateKeys = {
  '04b53d2415e45d34882665797abe8aca9896d8bf81890013bf52290be89a0227cb6922f226cae02b1a487351308978894c0d1b09f112c059a2a80cfe8367865fba':
  '44c5c85745a5ce977962f53e00451d9e0f920970a03ad8b6110737ec87674203',
  '04f78e3e1b75e0badd350e81ddc5f24d7a64c2b0cf524fc20068ca17eee0b1e21d2ca58c68deff1aa20f3c9b95eab4a9b1d45d4ee09434f3ebbaf3bcf5baff86fb':
  'e29cb5d295de3e58f6e1df7437578167f76407d78301d3199e68103356cb6c2e',
  '049d99dbe50b67b27462bea2f935a234b1b0493d7021c3c977d7cf9197c8a00d749270277bfa0eb327b7e3cdaf5c4b8b979c03d584dfd2a7f56e0cefb0381608ec':
  '3208074b7e5da795cb3a1f36d7f37dc1743c129152136808c8a7b8b902a60d1b',
}
*/

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, privateKey} = req.body;

  // Sign message
  const keyA = ec.keyFromPrivate(privateKey);
  const msgHash = SHA256(amount);
  const signature = keyA.sign(msgHash.toString());
  const splitSignature = {
    r: signature.r.toString(16),
    s: signature.s.toString(16)
  }

  // Verify message
  const keyB = ec.keyFromPublic(sender, 'hex');
  const verified = keyB.verify(msgHash.toString(), splitSignature);

  if (verified) {
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender], warning: "" });
  } else {
    res.send({ balance: balances[sender], warning: 'Incorrect private key'});
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
