const express = require("express");
const cors = require("cors");
const kyber = require("crystals-kyber");
const app = express();

app.use(
  cors({
    origin: ["http://localhost:3000", "*"],
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(require("cookie-parser")());
app.get("/", (req, res) => {
  try {
    let pk_sk = kyber.KeyGen768();
    let pk = pk_sk[0];
    let sk = pk_sk[1];

    // To generate a random 256 bit symmetric key (ss) and its encapsulation (c)
    let c_ss = kyber.Encrypt768(pk);
    let c = c_ss[0];
    let ss1 = c_ss[1];

    // To decapsulate and obtain the same symmetric key
    let ss2 = kyber.Decrypt768(c, sk);

    // Test function with KATs

    kyber.Test768();
    const formattedData = {
      pk: { pk },
      randomSymmetricKey_Encapsulation: { c },
      encrptedKey: { ss1 },
      decrptedKey: { ss2 },
    };
    const formattedJSON = JSON.stringify(formattedData, null, 2);
    res.status(200).send(formattedJSON);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.listen(3000, () => {
  console.log(`Server is running on port ${3000}`);
});
