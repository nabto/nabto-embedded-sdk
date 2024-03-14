
import { NabtoClientFactory } from 'edge-client-node'
const axios = require('axios').default;


async function main() {
  let client = NabtoClientFactory.create();
  let key = client.createPrivateKey();
  for (let i = 0; i<10; i++) {
    try {
    let connection = client.createConnection();
    connection.setOptions({ProductId: "pr-f4nqpowq", DeviceId: "de-jseuziej", PrivateKey: key});
    await connection.connect();
    console.log("i: ", i);
    const tunnel = connection.createTCPTunnel();
    await tunnel.open("http", 0);
    const localPort = tunnel.getLocalPort();

    const response = await axios.get(`http://127.0.0.1:${localPort}/`);

    await tunnel.close();
    await connection.close();
    } catch (err) {
      console.log(err);
    }
  }
}

main();

