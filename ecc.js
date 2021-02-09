//This file contains code for generating public key from private key using Elliptic Curve Cryptography
const Pcurve = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');

const Gx = BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240');
const Gy = BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424');

const G = [Gx, Gy];

const generatePublicKey = privateKey => {
    const ECCPoints = ECMultiply(G, privateKey);

    const checkKey = key => key.length < 64 ? '0'.repeat(64 - key.length)+key : key;

    const publicKeyX = checkKey(ECCPoints[0].toString(16));

    if (ECCPoints[1]%BigInt(2)===BigInt(1)) {
    return '03'+publicKeyX;
    } else {
    return '02'+publicKeyX;
    }
}

//mod inverse function
function modInverse(a, n) {

    a = (a % n + n) % n

    const dArray = [];
    let b = n;

    while(b) {
    [a, b] = [b, a % b];
    dArray.push({a, b});
    }

    if (a !== BigInt(1)) {
    return null;
    }

    let x = BigInt(1);
    let y = BigInt(0);

    for(let i = dArray.length - 2; i >= 0; --i) {
    [x, y] = [y,  x - y * BigInt(dArray[i].a / dArray[i].b)];
    }

    return (y % n + n) % n;
}

//mod of function
function modOf(a,b) {
    const r = ((a % b) + b)% b;
    return r;
}

//ECAdd - Elliptic Curve Addition Function
function ECAdd(a,b) {
    const lamAdd = modOf((b[1] - a[1]) * BigInt(modInverse(b[0] - a[0], Pcurve)), Pcurve);
    const x = modOf((lamAdd*lamAdd - a[0] - b[0]), Pcurve);
    const y = modOf((lamAdd*(a[0] - x) - a[1]), Pcurve);
    return [x, y];
}

//ECDouble - Elliptic Curve Point Doubling
function ECDouble(a) {
    const lamda = modOf(((BigInt(3)*a[0]*a[0])*(modInverse(BigInt(2)*a[1], Pcurve))), Pcurve);
    const x = modOf((lamda*lamda - BigInt(2)*a[0]), Pcurve);
    const y = modOf((lamda*(a[0] - x) - a[1]), Pcurve);
    return [x, y];
};

//ECMultiply - Ellptic Curve Multiplication
function ECMultiply(genPoint, pvtKey) {
    const scalarBinary = BigInt('0x'+pvtKey).toString(2);
    let GP = genPoint;

    for (let i=1; i < scalarBinary.length; i++) {
        GP = ECDouble(GP)
        if (scalarBinary[i] === '1') {
            GP = ECAdd(GP, genPoint);
        }
    }
    return GP;
}
