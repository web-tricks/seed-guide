//This function will take mnemonic code as the input and produce addresses
const detailsFromMnemonic = mnemonic => {

    // 1. Creating 'seed' from mnemonic code
    const salt = 'mnemonic'; //constant string 'mnemonic' used for salt in PBKDF2 function (custom passphrase could be used as well)
    const seed =  CryptoJS.PBKDF2(mnemonic, salt, {
        hasher:CryptoJS.algo.SHA512,
        keySize: 512 / 32,
        iterations:2048
    }).toString(); //using 2048 rounds of PBKDF2 key-stretching function

    // 2. Creating 'Master Private Key' and 'Chain Code' from 'seed'
    const hmacHash =  CryptoJS.HmacSHA512(CryptoJS.enc.Hex.parse(seed),'Bitcoin seed').toString();
    const masterPrivateKey = hmacHash.substr(0,64); //Left 256 bits of HMAC-512 hash
    const chainCode = hmacHash.substr(64,64); //Right 256 bits of HMAC-512 hash
    let masterPublicKey = generatePublicKey(masterPrivateKey);

    // 3. Generating childs using BIP-44 Derivation Path for LEGACY (Derivation Path - m/44'/0'/0'/0);
        // First Level: m/44':
        const [firstChildPrivate,firstChildPublic,firstChildChain] = generatingChild(masterPrivateKey,masterPublicKey,chainCode,'8000002c','private');
        // Second Level: m/44'/0':
        const [secondChildPrivate,secondChildPublic,secondChildChain] = generatingChild(firstChildPrivate,firstChildPublic,firstChildChain,'80000000','private');
        // Third Level: m/44'/0'/0':
        const [thirdChildPrivate,thirdChildPublic,thirdChildChain] = generatingChild(secondChildPrivate,secondChildPublic,secondChildChain,'80000000','private');
        // Fourth Level: m/44'/0'/0'/0 - For main receiving addresses:
        const [fourthChildPrivate,fourthChildPublic,fourthChildChain] = generatingChild(thirdChildPrivate,thirdChildPublic,thirdChildChain,'00000000','public');

        // Fifth Level: This level will be used for addresses
        //  We will generate 10 addresses from m/44'/0'/0'/0/0 to m/44'/0'/0'/0/9 branch to be used as receiving addresses
        let legacyAddresses = [];
        const legacyPrivateKeys = [];
        for (let i=0;i<10;i++) {
            const childSet = generatingChild(fourthChildPrivate,fourthChildPublic,fourthChildChain,'0000000'+i,'public');
            legacyAddresses.push(childSet[1]); //Pushing Public Key in the Array
            legacyPrivateKeys.push(childSet[0]); //Pushing Private Key in the Array
        }

        //  Converting Public Key in the Array to Legacy Bitcoin Addresses
        legacyAddresses = legacyAddresses.map(publicKey => generateLegacyAddress(publicKey));

    // 4. Generating childs using BIP-49 Derivation Path for P2SH (Derivation Path - m/49'/0'/0'/0);
        // First Level: m/49':
        const [firstChildPrivate49,firstChildPublic49,firstChildChain49] = generatingChild(masterPrivateKey,masterPublicKey,chainCode,'80000031','private');
        // Second Level: m/49'/0':
        const [secondChildPrivate49,secondChildPublic49,secondChildChain49] = generatingChild(firstChildPrivate49,firstChildPublic49,firstChildChain49,'80000000','private');
        // Third Level: m/49'/0'/0':
        const [thirdChildPrivate49,thirdChildPublic49,thirdChildChain49] = generatingChild(secondChildPrivate49,secondChildPublic49,secondChildChain49,'80000000','private');
        // Fourth Level: m/49'/0'/0'/0 - For main receiving addresses:
        const [fourthChildPrivate49,fourthChildPublic49,fourthChildChain49] = generatingChild(thirdChildPrivate49,thirdChildPublic49,thirdChildChain49,'00000000','public');

        // Fifth Level: This level will be used for addresses
        //  We will generate 10 addresses from m/49'/0'/0'/0/0 to m/49'/0'/0'/0/9 branch to be used as receiving addresses
        let p2shAddresses = [];
        const p2shPrivateKeys = [];
        for (let i=0;i<10;i++) {
            const childSet = generatingChild(fourthChildPrivate49,fourthChildPublic49,fourthChildChain49,'0000000'+i,'public');
            p2shAddresses.push(childSet[1]); //Pushing Public Key in the Array
            p2shPrivateKeys.push(childSet[0]); //Pushing Private Key in the Array
        }

       //  Converting Public Key in the Array to P2SH Bitcoin Addresses
       p2shAddresses = p2shAddresses.map(publicKey => generateP2SHAddress(publicKey));
    
    return {
        masterPrivateKey,
        masterPublicKey,
        legacyPrivateKeys,
        legacyAddresses,
        p2shAddresses,
        p2shPrivateKeys
    }
}

//Function to generate child private key, child public key and child chain code
function generatingChild(parentPrivateKey, parentPublicKey, parentChainCode,index,type) {
    let parentPrivate = parentPrivateKey.length === 64 ? parentPrivateKey : '0'.repeat(64-parentPrivateKey.length)+parentPrivateKey;
    const keyToUse = type === 'private' ? '00'+parentPrivate : parentPublicKey; //Use private key if hardened-index else public key
    const hmacHash = CryptoJS.HmacSHA512(CryptoJS.enc.Hex.parse(keyToUse+index),CryptoJS.enc.Hex.parse(parentChainCode)).toString();
    const [leftBits,childChainCode] = separateKeyChain(hmacHash);
    const N = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'; //As defined in secp256k1 ecc
    let childPrivateKey = (BigInt('0x'+parentPrivate) + BigInt('0x'+leftBits)) % BigInt(N);
    childPrivateKey = childPrivateKey.toString(16); //Converting from decimal to hex
    const childPublicKey = generatePublicKey(childPrivateKey); //Using ECC function taken from 'ecc.js' file

    return [childPrivateKey,childPublicKey,childChainCode];
}

//Function to be used in generatingChild function to separate hash into private key and chain code
function separateKeyChain(hmacHash) {
    const privateKeyPart = hmacHash.substr(0,64);
    const chainCodePart = hmacHash.substr(64,64);
    return [privateKeyPart,chainCodePart];
}