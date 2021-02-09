//This function will generate Legacy bitcoin address (public key hash) using public key
const generateLegacyAddress = (publicKey) => {
    const keyHex = CryptoJS.enc.Hex.parse(publicKey);
    const ripedHashedKey = CryptoJS.RIPEMD160(CryptoJS.SHA256(keyHex)).toString();
    const mainRipeKeyString = '00'+ripedHashedKey;
    const mainRipeKey = CryptoJS.enc.Hex.parse(mainRipeKeyString);
    const doubleHashedKey = CryptoJS.SHA256(CryptoJS.SHA256(mainRipeKey)).toString();
    const checkSum = doubleHashedKey.substr(0, 8);
    const binaryAddress = mainRipeKeyString+checkSum;
    const arrayBinary = binaryAddress.match(/.{1,2}/g); //Converting serialization into array of every 2nd character
    const binaryUint = new Uint8Array(arrayBinary.map(hex => parseInt(hex,16))); //Converting hex array into uint8array to be used as input in base58 function
    
    return to_b58(binaryUint,bs58Chars);
}


