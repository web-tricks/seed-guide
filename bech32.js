//This function will generate P2SH bitcoin address (P2WPKH-in-P2SH) using public key
const generateBech32Address = (publicKey) => {
    const bech32schema = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    const keyHex = CryptoJS.enc.Hex.parse(publicKey);
    const ripeHash = CryptoJS.RIPEMD160(CryptoJS.SHA256(keyHex)).toString();

    let binString = BigInt('0x'+ripeHash).toString(2);
    binString = binString.length === 160 ? binString : '0'.repeat(160-binString.length)+binString;

    const decArray = binString.match(/.{1,5}/g).map(binary => parseInt(binary,2));
    decArray.unshift(0);

    const checkSum = createChecksum(decArray);

    const hexString = decArray.map(decimal => ('00'+decimal.toString(16)).substr(-2)).join('');

    let address = '';

    (hexString+checkSum).match(/.{1,2}/g).forEach(hexVal => {
        address += bech32schema[parseInt(hexVal,16)];
    });
    
    return 'bc1'+address;
}

//Checksum generation using BCH Codes
function createChecksum(decArr) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1

    let decArray = [3,3,0,2,3].concat(decArr)
    decArray = decArray.concat([0,0,0,0,0,0]);
    
    decArray.forEach(dec => {
        let b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ dec;

        for (let i=0;i<5;i++) {
            chk ^= ((b >> i) & 1) ? GEN[i] : 0;
        }
    });

    const polymod = chk ^ 1;

    const returnVal = [];

    for (let v=0;v<6;v++) {
        returnVal.push((polymod >> 5 * (5 - v)) & 31)
    }

    return returnVal.map(val => ('00'+val.toString(16)).substr(-2)).join('');
}