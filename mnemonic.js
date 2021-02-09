//Generating random 128 bits. 128 - 256 bits can be used but for this tutorial we are strictly generating 128 bits entropy
const getRandomBytes = () => {
    const array = new Uint32Array(4); //creating Uint32 array having length = 4
    const randomBytes = crypto.getRandomValues(array); //Filling array with random 32-bits integers

    let binaryString = '';
    let hexString = ''; 
    randomBytes.forEach(byte => {
        let binChunk = byte.toString(2);
        binChunk = binChunk.length === 32 ? binChunk : '0'.repeat(32 - binChunk.length)+binChunk;
        let hexChunk = parseInt(binChunk,2).toString(16);

        binaryString += binChunk;
        hexString += hexChunk;
    })

    return [binaryString,hexString];
}

//Generating SHA-256 hash of random bytes for checksum
let [randomBits,randomBitsHex] = getRandomBytes();
const byteHash = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(randomBitsHex)).toString(); //SHA-256 Hash of random bytes
let checksum = parseInt(byteHash[0],16).toString(2); //Taking (entropy-length / 32) bits of SHA256 hash which in our case is 4 bits
checksum = checksum.length === 4 ? checksum : '0'.repeat(4 - checksum.length)+checksum; //Adding '0' bits if hex is smaller than '8' or '0b1000' in binary

//Adding checksum at the end of random bytes
randomBits += checksum; 

//Splitting random bytes into segments of 11-bits length and storing in an array
const segmentArray = [];
let i = 0;
while (i < randomBits.length) {
    segmentArray.push(randomBits.substring(i,i+11));
    i += 11;
}

//Converting every 11-bits segment into decimal equivalent
const decimalArray = segmentArray.map(segment => parseInt(segment,2));

//Picking 'word' at position equivalent to decimal array from 'mnemonic words list' (words.js)
const mnemonicArray = decimalArray.map(decimal => wordsArray[decimal]);

//getMnemonic Function - This function will be called in front-end when user will create new seed
const getMnemonic = () => {
    return mnemonicArray.join(' '); //Converting mnemonic array into mnemonic string
}