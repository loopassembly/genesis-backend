const Web3 = require('web3');
const fs = require('fs');
const dotenv = require('dotenv');
dotenv.config();
const args = process.argv.slice(2);
const axieId = args[0];
const roninAddress = args[1];


const provider = 'https://api.roninchain.com/rpc';
const web3 = new Web3(new Web3.providers.HttpProvider(provider));

const contractAddress = '0x32950db2a7164ae833121501c797d79e7b79d74c';
const contractABI = JSON.parse(fs.readFileSync('app/wallet_intigration/abi.json', 'utf8'));
const contract = new web3.eth.Contract(contractABI, contractAddress);

const senderAddress = '0x9396ab9bcfe83bae69052f1ff6f05bcbab8c17c8';
const receiverAddress = roninAddress;
const tokenId = axieId;

async function transferNFT() {
  const gasPrice = await web3.eth.getGasPrice();
  const gasEstimate = await contract.methods.transferFrom(senderAddress, receiverAddress, tokenId).estimateGas({ from: senderAddress });

  const privateKey = process.env.PRIVATE_KEY;
  console.log(privateKey);

  const tx = {
    from: senderAddress,
    to: contractAddress,
    gas: gasEstimate,
    gasPrice,
    data: contract.methods.transferFrom(senderAddress, receiverAddress, tokenId).encodeABI(),
  };

  const signedTx = await web3.eth.accounts.signTransaction(tx, privateKey);
  const txHash = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
  console.log(`Transaction hash: ${txHash}`);
}

transferNFT().catch(console.error);