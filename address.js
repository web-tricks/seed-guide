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

    // 3. Generating childs using BIP-44 Derivation Path for LEGACY (Derivation Path - m/44'/0'/0'/0); - Hardened Child - 0x8000002c
        let {addresses: legacyAddresses, privateKeys: legacyPrivateKeys} = returnChild(masterPrivateKey,masterPublicKey,chainCode,'8000002c');
        //  Converting Public Key in the Array to Legacy Bitcoin Addresses
        legacyAddresses = legacyAddresses.map(publicKey => generateLegacyAddress(publicKey));

    // 4. Generating childs using BIP-49 Derivation Path for P2SH (Derivation Path - m/49'/0'/0'/0); - Hardened Child - 0x80000031
        let {addresses: p2shAddresses, privateKeys: p2shPrivateKeys} = returnChild(masterPrivateKey,masterPublicKey,chainCode,'80000031');
       //  Converting Public Key in the Array to P2SH Bitcoin Addresses
       p2shAddresses = p2shAddresses.map(publicKey => generateP2SHAddress(publicKey));
    
    // 5. Generating childs using BIP-84 Derivation Path for Bech32 (Derivation Path - m/84'/0'/0'/0); - Hardened Child - 0x80000054
        let {addresses: bech32Addresses, privateKeys: bech32PrivateKeys} = returnChild(masterPrivateKey,masterPublicKey,chainCode,'80000054');
       //  Converting Public Key in the Array to P2SH Bitcoin Addresses
       bech32Addresses = bech32Addresses.map(publicKey => generateBech32Address(publicKey));
       
    return {
        masterPrivateKey,
        masterPublicKey,
        legacyPrivateKeys,
        legacyAddresses,
        p2shAddresses,
        p2shPrivateKeys,
        bech32Addresses,
        bech32PrivateKeys
    }
}

//Function for Deriving Children based on Hardened Child
function returnChild(masterPrivateKey,masterPublicKey,chainCode,hardenedChild) {
    // First Level: m/H':
    const [firstChildPrivate,firstChildPublic,firstChildChain] = generatingChild(masterPrivateKey,masterPublicKey,chainCode,hardenedChild,'private');
    // Second Level: m/H'/0':
    const [secondChildPrivate,secondChildPublic,secondChildChain] = generatingChild(firstChildPrivate,firstChildPublic,firstChildChain,'80000000','private');
    // Third Level: m/H'/0'/0':
    const [thirdChildPrivate,thirdChildPublic,thirdChildChain] = generatingChild(secondChildPrivate,secondChildPublic,secondChildChain,'80000000','private');
    // Fourth Level: m/H'/0'/0'/0 - For main receiving addresses:
    const [fourthChildPrivate,fourthChildPublic,fourthChildChain] = generatingChild(thirdChildPrivate,thirdChildPublic,thirdChildChain,'00000000','public');

    // Fifth Level: This level will be used for addresses
    //  We will generate 10 addresses from m/H'/0'/0'/0/0 to m/H'/0'/0'/0/9 branch to be used as receiving addresses
    let addresses = [];
    const privateKeys = [];
    for (let i=0;i<10;i++) {
        const childSet = generatingChild(fourthChildPrivate,fourthChildPublic,fourthChildChain,'0000000'+i,'public');
        addresses.push(childSet[1]); //Pushing Public Key in the Array
        privateKeys.push(childSet[0]); //Pushing Private Key in the Array
    }

    return {
        addresses,
        privateKeys
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