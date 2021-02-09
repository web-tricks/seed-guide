//This function will generate P2SH bitcoin address (P2WPKH-in-P2SH) using public key
const generateP2SHAddress = (publicKey) => {
    const keyHex = CryptoJS.enc.Hex.parse(publicKey);
    const ripeHash = CryptoJS.RIPEMD160(CryptoJS.SHA256(keyHex)).toString();

    const script = '0014'+ripeHash;
    const scriptHex = CryptoJS.enc.Hex.parse(script);
    const scriptRipeHash = '05'+CryptoJS.RIPEMD160(CryptoJS.SHA256(scriptHex)).toString();

    const doubleHashedKey = CryptoJS.SHA256(CryptoJS.SHA256(scriptRipeHash)).toString();
    const checkSum = doubleHashedKey.substr(0, 8);

    const binaryAddress = scriptRipeHash+checkSum;

    const arrayBinary = binaryAddress.match(/.{1,2}/g); //Converting serialization into array of every 2nd character
    const binaryUint = new Uint8Array(arrayBinary.map(hex => parseInt(hex,16))); //Converting hex array into uint8array to be used as input in base58 function
    
    return to_b58(binaryUint,bs58Chars);
}