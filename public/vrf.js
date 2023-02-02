const copyToClipboard = (str) => {
	const el = document.createElement('textarea');
	el.value = str;
	el.setAttribute('readonly', '');
	el.style.position = 'absolute';
	el.style.left = '-9999px';
	document.body.appendChild(el);
	el.select();
	document.execCommand('copy');
	document.body.removeChild(el);
};

function checkOverflow (el) {
	let curOverflow = el.style.overflow;
	if (!curOverflow || curOverflow === "visible") {
		el.style.overflow = "hidden";
	}
	let isOverflowing = el.clientWidth < el.scrollWidth || el.clientHeight < el.scrollHeight;
	el.style.overflow = curOverflow;
	return isOverflowing;
}

function downloadObjectAsJson(exportObj, exportName) {
	let dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportObj, null, 2));
	let downloadAnchorNode = document.createElement('a');
	downloadAnchorNode.setAttribute("href", dataStr);
	downloadAnchorNode.setAttribute("download", exportName + ".json");
	document.body.appendChild(downloadAnchorNode);
	downloadAnchorNode.click();
	downloadAnchorNode.remove();
}

function removeAllChildNodes (parent) {
	while (parent.firstChild) {
		parent.removeChild(parent.firstChild);
	}
}

function removeByIndex(str, index) {
	return str.slice(0,index) + str.slice(index+1);
}

let pageWrapper = document.getElementById("page-wrapper");
let vrfWrapper = document.getElementById("vrf-wrapper");
let title = document.getElementById("title");
let algoDisplay = document.getElementById("algorithms");
let algoContent1 = document.getElementById("new-wrapper");
let algoContent2 = document.getElementById("list-wrapper");
let algoContent3 = document.getElementById("separator");
let searchInput = document.getElementById("searchInput");
let dropdown = document.getElementById("dropdown");
let dropdownElements = document.getElementById("dropdownElements");
let editDisplay = document.getElementById("currentAlgo");
let outputWrapper = document.getElementById("output-wrapper");
let vrfDisplay = document.getElementById("output");
let extractWrapper = document.getElementById("extract-wrapper");
let copyBtn = document.getElementById("copyBtn");
let downloadBtn = document.getElementById("downloadBtn");
let loadBtn = document.getElementById("loadBtn");
let outputMinimize = document.getElementById("outputMinimize");
let algorithmsMinimize = document.getElementById("algorithmsMinimize");

let currentAlgo = -1;

let vrf = [];
let version = {"acvVersion": "1.0"};
let algos = [];
let algoObjectWrapper = {"isSample": true};
algoObjectWrapper["algorithms"] = algos;
vrf.push(version);
vrf.push(algoObjectWrapper);

function updateScreenHeight () {
	pageWrapper.style.height = Math.max(vrfWrapper.clientHeight + 100, window.innerHeight) + 'px';
}

function updateVrfDisplay () {
	vrfDisplay.textContent = JSON.stringify(vrf, null, 2);
}

updateVrfDisplay();
updateScreenHeight();

const ACVPalgos = ["SHA-1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512-224", "SHA2-512-256",

	"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256",

	"ACVP-AES-ECB", "ACVP-AES-CBC", "ACVP-AES-CBC-CS1", "ACVP-AES-CS2", "ACVP-AES-CBC-CS3", "ACVP-AES-OFB", "ACVP-AES-CFB1", "ACVP-AES-CFB8",
	"ACVP-AES-CFB128", "ACVP-AES-CTR", "ACVP-AES-FF1", "ACVP-AES-FF3-1", "ACVP-AES-GCM", "ACVP-AES-GCM-SIV", "ACVP-AES-XPN", "ACVP-AES-CCM",
	"ACVP-AES-XTS", "ACVP-AES-KW", "ACVP-AES-KWP", "ACVP-TDES-ECB", "ACVP-TDES-CBC", "ACVP-TDES-CBCI", "ACVP-TDES-CFB1", "ACVP-TDES-CFB8",
	"ACVP-TDES-CFB64", "ACVP-TDES-CFBP1", "ACVP-TDES-CFBP8", "ACVP-TDES-CFBP64", "ACVP-TDES-OFB", "ACVP-TDES-OFBI", "ACVP-TDES-CTR", "ACVP-TDES-KW",

	"cSHAKE-128", "cSHAKE-256", "KMAC-128", "KMAC-256", "ParallelHash-128", "ParallelHash-256", "TupleHash-128", "TupleHash-256",

	"HMAC-SHA-1", "HMAC-SHA2-224", "HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512", "HMAC-SHA2-512/224", "HMAC-SHA2-512/256", "HMAC-SHA3-224",
	"HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512", "CMAC-AES", "CMAC-TDES", "ACVP-AES-GMAC",

	"safePrimes",

	"ikev1", "ikev2",

	"SNMP", "SRTP", "SSH",

	"tls",

	"signaturePrimitive", "decryptionPrimitive"];

const group1 = ["ACVP-AES-ECB", "ACVP-AES-CBC", "ACVP-AES-OFB", "ACVP-AES-CFB1", "ACVP-AES-CFB8", "ACVP-AES-CFB128"];
const group2 = ["ACVP-TDES-ECB", "ACVP-TDES-CBC", "ACVP-TDES-CBCI", "ACVP-TDES-CFB1", "ACVP-TDES-CFB8", "ACVP-TDES-CFB64", "ACVP-TDES-CFBP1",
	"ACVP-TDES-CFBP8", "ACVP-TDES-CFBP64", "ACVP-TDES-OFB", "ACVP-TDES-OFBI"];
const group3 = ["ACVP-AES-CBC-CS1", "ACVP-AES-CBC-CS2", "ACVP-AES-CBC-CS3"];
const group4 = ["HMAC-SHA-1", "HMAC-SHA2-224", "HMAC-SHA2-256", "HMAC-SHA2-384", "HMAC-SHA2-512", "HMAC-SHA2-512/224", "HMAC-SHA2-512/256",
	"HMAC-SHA3-224", "HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512"];

const maxMACLengths = [160, 224, 256, 384, 512, 224, 256, 224, 256, 384, 512];

function updateEditDisplay () {
	removeAllChildNodes(editDisplay);

	let editTitle = document.createElement("div");
	editTitle.id = "editTitle";
	if (currentAlgo >= 13 && currentAlgo <= 44 || currentAlgo == 66) {
		//ACVP symmetric
		editTitle.textContent = ACVPalgos[currentAlgo].substring(5);
	} else if (currentAlgo == 67) {
		editTitle.textContent = "Safe Primes";
	} else if (ACVPalgos[currentAlgo] == "ikev1") {
		editTitle.textContent = "IKEv1";
	} else if (ACVPalgos[currentAlgo] == "ikev2") {
		editTitle.textContent = "IKEv2";
	} else if (ACVPalgos[currentAlgo] == "tls") {
		editTitle.textContent = "TLS";
	} else if (ACVPalgos[currentAlgo] == "signaturePrimitive") {
		editTitle.textContent = "RSA Signature Primitive";
	} else if (ACVPalgos[currentAlgo] == "decryptionPrimitive") {
		editTitle.textContent = "RSA Decryption Primitive";
	} else {
		editTitle.textContent = ACVPalgos[currentAlgo];
	}
	editDisplay.appendChild(editTitle);

	let algoIndex = -1;
	for (let i=0; i<algos.length; i++) {
		if (algos[i]["algorithm"] == ACVPalgos[currentAlgo]) {
			algoIndex = i;
		}
	}

	if (algoIndex == -1) {
		for (let i=0; i<algos.length; i++) {
			if (algos[i]["mode"] == ACVPalgos[currentAlgo]) {
				algoIndex = i;
			}
		}
	}

	if (currentAlgo < 11) {
		//SHA-1, SHA-2, SHA-3
		createLengthLink(algos[algoIndex], "messageLength", "Message Length", "The message lengths, in bits, supported by the IUT", 0, 65535, true);
		createOptionLink(algos[algoIndex], "performLargeDataTest", "Large Data Test Sizes", "(Optional) Determines the lengths, in GiB (if any), of large data tests to be performed by the server. These tests perform the hash function on very long messages in order to push the bounds of 32-bit data types and ensure an implementation can handle all types of data.", [["1 GiB", 1], ["2 GiB", 2], ["4 GiB", 4], ["8 GiB", 8]], true);
	} else if (currentAlgo < 13) {
		//SHAKE
		createBooleanLink(algos[algoIndex], "inBit", "Allow bit messages", "True if implementation accepts bit-oriented messages, false if implementation only accepts byte-oriented messages (messages with lengths that are divisible by 8)");
		createBooleanLink(algos[algoIndex], "inEmpty", "Allow empty messages", "True if implementation accepts null messages of length zero");
		createBooleanLink(algos[algoIndex], "outBit", "Output bit messages", "True if SHAKE can output bit-oriented messages, false if implementation only outputs byte-oriented messages (messages with lengths divisible by 8)");
		createLengthLink(algos[algoIndex], "outputLen", "Output Length", "Output length of SHAKE in bits", 0, 65535, false);
	} else if (group1.indexOf(ACVPalgos[currentAlgo]) != -1) {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
	} else if (group2.indexOf(ACVPalgos[currentAlgo]) != -1) {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyingOption", "Keying Option", "The keying option used in TDES. Option 1 is for 3 distinct keys, option 2 is for 2 distinct keys. NOTE: option 2 is only allowed for decrypt", [["1", 1], ["2", 2]], true);
		document.getElementById("keyingOptionoption2").addEventListener("click", () => {
			if (document.getElementById("keyingOptionoption2").selected == true && document.getElementById("directionoptiondecrypt").selected == false) {
				document.getElementById("keyingOptionoption2").selected = false;
				algos[algoIndex]["keyingOption"].splice(algos[algoIndex]["keyingOption"].indexOf(2), 1);
				updateVrfDisplay();
			}
		});
		document.getElementById("directionoption").addEventListener("click", () => {
			if (document.getElementById("directionoptiondecrypt").selected == false) {
				document.getElementById("keyingOptionoption2").selected = false;
				algos[algoIndex]["keyingOption"].splice(algos[algoIndex]["keyingOption"].indexOf(2), 1);
				updateVrfDisplay();
			}
		});
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-KW" || ACVPalgos[currentAlgo] == "ACVP-AES-KWP") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createOptionLink(algos[algoIndex], "kwCipher", "Key Wrap Cipher", "The cipher as defined in SP800-38F for key wrap mode. \"Cipher\" will use the same direction as specified for the underlying AES operion while \"inverse\" will flip it (encrypt direction with inverse key wrap cipher will use decrypt for the underlying AES operation)", [["Cipher", "cipher"], ["Inverse", "inverse"]], true);
		if (ACVPalgos[currentAlgo] == "ACVP-AES-KW") {
			createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 128, 4096, false);
		} else if (ACVPalgos[currentAlgo] == "ACVP-AES-KWP") {
			createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 8, 4096, false);
		}
	} else if (ACVPalgos[currentAlgo] == "ACVP-TDES-KW") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "kwCipher", "Key Wrap Cipher", "The cipher as defined in SP800-38F for key wrap mode. \"Cipher\" will use the same direction as specified for the underlying AES operion while \"inverse\" will flip it (encrypt direction with inverse key wrap cipher will use decrypt for the underlying AES operation)", [["Cipher", "cipher"], ["Inverse", "inverse"]], true);
		createOptionLink(algos[algoIndex], "keyingOption", "Keying Option", "The keying option used in TDES. Option 1 is for 3 distinct keys, option 2 is for 2 distinct keys. NOTE: option 2 is only allowed for decrypt", [["1", 1], ["2", 2]], true);
		document.getElementById("keyingOptionoption2").addEventListener("click", () => {
			if (document.getElementById("keyingOptionoption2").selected == true && document.getElementById("directionoptiondecrypt").selected == false) {
				document.getElementById("keyingOptionoption2").selected = false;
				algos[algoIndex]["keyingOption"].splice(algos[algoIndex]["keyingOption"].indexOf(2), 1);
				updateVrfDisplay();
			}
		});
		document.getElementById("directionoption").addEventListener("click", () => {
			if (document.getElementById("directionoptiondecrypt").selected == false) {
				document.getElementById("keyingOptionoption2").selected = false;
				algos[algoIndex]["keyingOption"].splice(algos[algoIndex]["keyingOption"].indexOf(2), 1);
				updateVrfDisplay();
			}
		});
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 64, 4096, false);
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-GCM") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 0, 65536, true);
		createLengthLink(algos[algoIndex], "ivLen", "IV Length", "The supported initialization vector/nonce lengths in bits", 8, 1024, true);
		createOptionLink(algos[algoIndex], "ivGen", "IV Generation", "The method of generating initialization vectors. Internal if and only if generation is done within the cryptographic module", [["Internal", "internal"], ["External", "external"]], false);
		createOptionLink(algos[algoIndex], "ivGenMode", "IV Generation Mode", "Which initialization vector construction method the implementation conforms to as defined in SP 800-38D. The value represents the section number of the definition -- 8.2.1 is deterministic and 8.2.2 is RBG-based", [["8.2.1", "8.2.1"], ["8.2.2", "8.2.2"]], false);
		createLengthLink(algos[algoIndex], "aadLen", "AAD Length", "The length of additional authenticated data to use, in bits", 0, 65536, true);
		createOptionLink(algos[algoIndex], "tagLen", "Tag Length", "The supported lengths of authentication tag for authenticated encryption with associated data (AEAD), in bits", [["32", 32], ["64", 64], ["96", 96], ["104", 104], ["112", 112], ["120", 120], ["128", 128]], true);
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-GCM-SIV") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 0, 65536, false);
		createLengthLink(algos[algoIndex], "aadLen", "AAD Length", "The length of additional authenticated data to use, in bits", 0, 65536, false);
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-XPN") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 0, 65536, true);
		createOptionLink(algos[algoIndex], "ivGen", "IV Generation", "The method of generating initialization vectors. Internal if and only if generation is done within the cryptographic module", [["Internal", "internal"], ["External", "external"]], false);
		createOptionLink(algos[algoIndex], "ivGenMode", "IV Generation Mode", "Which initialization vector construction method the implementation conforms to as defined in SP 800-38D. The value represents the section number of the definition -- 8.2.1 is deterministic and 8.2.2 is RBG-based", [["8.2.1", "8.2.1"], ["8.2.2", "8.2.2"]], false);
		createOptionLink(algos[algoIndex], "saltGen", "Salt Generation Method", "Set to internal if salt is generated within the cryptographic module, external otherwise", [["Internal", "internal"], ["External", "external"]], false);
		createLengthLink(algos[algoIndex], "aadLen", "AAD Length", "The length of additional authenticated data to use, in bits", 1, 65536, true);
		createOptionLink(algos[algoIndex], "tagLen", "Tag Length", "The supported lengths of authentication tag for authenticated encryption with associated data (AEAD), in bits", [["32", 32], ["64", 64], ["96", 96], ["104", 104], ["112", 112], ["120", 120], ["128", 128]], true);
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-CCM") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 0, 256, false);
		createLengthLink(algos[algoIndex], "ivLen", "IV Length", "The supported initialization vector/nonce lengths in bits", 56, 104, false);
		createLengthLink(algos[algoIndex], "aadLen", "AAD Length", "The length of additional authenticated data to use, in bits", 0, 524288, true);
		createOptionLink(algos[algoIndex], "tagLen", "Tag Length", "The supported lengths of authentication tag for authenticated encryption with associated data (AEAD), in bits", [["32", 32], ["48", 48], ["64", 64], ["80", 80], ["96", 96], ["112", 112], ["128", 128]], true);
		createOptionLink(algos[algoIndex], "conformances", "Conformances", "The optional conformance for a specific use-case. ECMA refers to the ECMA-368, high rate ultra wideband PHY and MAC standard, which changes the supported sizes to accomododate", [["ECMA", "ECMA"]], true);
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-XTS") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 128, 65536, false);
		createOptionLink(algos[algoIndex], "tweakMode", "Tweak Mode", "Indicates the format(s) of the tweak value input. A value of \"hex\" indicates that the IUT expects the tweak value input as a hexadecimal string", [["Hex", "hex"], ["Number", "number"]], true);
		createBooleanLink(algos[algoIndex], "dataUnitLenMatchesPayload", "Unit Length Matches Payload", "A data unit is a means of logically breaking apart a data stream provided to the encryption algorithm. Setting this to true will force the data unit length to match the payload length");
		if (document.getElementById("dataUnitLenMatchesPayloadbox").checked == false) {
				updateScreenHeight();
				createLengthLink(algos[algoIndex], "dataUnitLen", "Data Unit Length", "A data unit is a means of logically breaking apart a data stream provided to the encryption algorithm. This length, in bits, maybe be larger, smaller, or equal to the payload being processed", 128, 65536, false);
		}
		document.getElementById("dataUnitLenMatchesPayloadbox").addEventListener("click", () => {
			if (document.getElementById("dataUnitLenMatchesPayloadbox").checked == false) {
				algos[algoIndex]["dataUnitLen"] = [{
					"min": 128,
					"max": 65536,
					"increment": 8
				}];
				createLengthLink(algos[algoIndex], "dataUnitLen", "Data Unit Length", "A data unit is a means of logically breaking apart a data stream provided to the encryption algorithm. This length, in bits, maybe be larger, smaller, or equal to the payload being processed", 128, 65536, false);
			} else {
				editDisplay.removeChild(document.getElementById("dataUnitLen"));
				delete algos[algoIndex]["dataUnitLen"];
			}
			updateScreenHeight();
		});
	} else if (group3.indexOf(ACVPalgos[currentAlgo]) != -1) {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 128, 65536, true);
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-CTR") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 1, 128, true);
		createBooleanLink(algos[algoIndex], "overflowCounter", "Overflow Counter", "Indicates if the implementation can handle a counter exceeding the maximum value");
		createBooleanLink(algos[algoIndex], "incrementalCounter", "Incremental Counter", "Indicates if the implementation increments the counter (versus decrementing the counter)");
		createBooleanLink(algos[algoIndex], "performCounterTests", "Perform Counter Tests", "	Indicates if the implementation can perform the Counter tests which check for an always increasing (or decreasing) counter value");
		createOptionLink(algos[algoIndex], "conformances", "Conformances", "The optional conformance for a specific use-case. RFC3686 ensures the IV is generated with the LSB[32] of the IV representing the integer 1. This also requires ivGenMode property.", [["RFC3686", "RFC3686"]], true);
		if (algos[algoIndex]["ivGenMode"]) {
			createOptionLink(algos[algoIndex], "ivGenMode", "IV Generation Mode", "Which initialization vector construction method the implementation conforms to as defined in SP 800-38D. The value represents the section number of the definition -- 8.2.1 is deterministic and 8.2.2 is RBG-based", [["8.2.1", "8.2.1"], ["8.2.2", "8.2.2"]], false);
		}
		document.getElementById("conformancesoptionRFC3686").addEventListener("click", () => {
			if (document.getElementById("conformancesoptionRFC3686").selected == true) {
				if (!algos[algoIndex]["ivGenMode"]) {
					algos[algoIndex]["ivGenMode"] = "";
					createOptionLink(algos[algoIndex], "ivGenMode", "IV Generation Mode", "Which initialization vector construction method the implementation conforms to as defined in SP 800-38D. The value represents the section number of the definition -- 8.2.1 is deterministic and 8.2.2 is RBG-based", [["8.2.1", "8.2.1"], ["8.2.2", "8.2.2"]], false);
					updateVrfDisplay();
				}
			} else {
				document.getElementById("ivGenMode").remove();
				delete algos[algoIndex]["ivGenMode"];
			}
		});
	} else if (ACVPalgos[currentAlgo] == "ACVP-TDES-CTR") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createLengthLink(algos[algoIndex], "payloadLen", "Payload Length", "The length of plaintext or ciphertext in bits to use", 1, 64, true);
		createBooleanLink(algos[algoIndex], "overflowCounter", "Overflow Counter", "Indicates if the implementation can handle a counter exceeding the maximum value");
		createBooleanLink(algos[algoIndex], "incrementalCounter", "Incremental Counter", "Indicates if the implementation increments the counter (versus decrementing the counter)");
		createBooleanLink(algos[algoIndex], "performCounterTests", "Perform Counter Tests", "	Indicates if the implementation can perform the Counter tests which check for an always increasing (or decreasing) counter value");
		createOptionLink(algos[algoIndex], "keyingOption", "Keying Option", "The keying option used in TDES. Option 1 is for 3 distinct keys, option 2 is for 2 distinct keys. NOTE: option 2 is only allowed for decrypt", [["1", 1], ["2", 2]], true);
		document.getElementById("keyingOptionoption2").addEventListener("click", () => {
			if (document.getElementById("keyingOptionoption2").selected == true && document.getElementById("directionoptiondecrypt").selected == false) {
				document.getElementById("keyingOptionoption2").selected = false;
				algos[algoIndex]["keyingOption"].splice(algos[algoIndex]["keyingOption"].indexOf(2), 1);
				updateVrfDisplay();
			}
		});
		document.getElementById("directionoption").addEventListener("click", () => {
			if (document.getElementById("directionoptiondecrypt").selected == false) {
				document.getElementById("keyingOptionoption2").selected = false;
				algos[algoIndex]["keyingOption"].splice(algos[algoIndex]["keyingOption"].indexOf(2), 1);
				updateVrfDisplay();
			}
		});
		createOptionLink(algos[algoIndex], "conformances", "Conformances", "The optional conformance for a specific use-case. RFC3686 ensures the IV is generated with the LSB[32] of the IV representing the integer 1. This also requires ivGenMode property.", [["RFC3686", "RFC3686"]], true);
		if (algos[algoIndex]["ivGenMode"]) {
			createOptionLink(algos[algoIndex], "ivGenMode", "IV Generation Mode", "Which initialization vector construction method the implementation conforms to as defined in SP 800-38D. The value represents the section number of the definition -- 8.2.1 is deterministic and 8.2.2 is RBG-based", [["8.2.1", "8.2.1"], ["8.2.2", "8.2.2"]], false);
		}
		document.getElementById("conformancesoptionRFC3686").addEventListener("click", () => {
			if (document.getElementById("conformancesoptionRFC3686").selected == true) {
				if (!algos[algoIndex]["ivGenMode"]) {
					algos[algoIndex]["ivGenMode"] = "";
					createOptionLink(algos[algoIndex], "ivGenMode", "IV Generation Mode", "Which initialization vector construction method the implementation conforms to as defined in SP 800-38D. The value represents the section number of the definition -- 8.2.1 is deterministic and 8.2.2 is RBG-based", [["8.2.1", "8.2.1"], ["8.2.2", "8.2.2"]], false);
					updateVrfDisplay();
				}
			} else {
				document.getElementById("ivGenMode").remove();
				delete algos[algoIndex]["ivGenMode"];
			}
		});
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-FF1" || ACVPalgos[currentAlgo] == "ACVP-AES-FF3-1") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);

		let fieldWrapper = document.createElement("div");
		fieldWrapper.id = "capabilities";
		fieldWrapper.classList.add("fieldWrapper");

		fieldWrapper.innerHTML = `
			<div class="inputWrapper">
				<div class="fieldLabel" title="An alphabet the IUT supports for Format Preserving Encryption. Alphabets should be a minimum of two characters and a maximum of 64 (all numbers and upper and lower case letters, additionally \"+\" and \"/\"">Alphabet:</div>
				<input class="fieldInput" type="text" id="capabilitiesalphabet" name="capabilitiesalphabet" minlength="2" maxlength="64" size="26">
			</div>
			<div class="inputWrapper">
				<div class="fieldLabel" title="The minimum payload length the IUT can support for this alphabet. Note that the number of characters in the alphabet raised to the minimum length must be greater than or equal to one million">Payload Length Minimum:</div>
				<input class="fieldInput" type="number" id="payloadmin" name="payloadmin" min="2" max="4294967296" value="2">
			</div>
			<div class="inputWrapper">
				<div class="fieldLabel" title="The maximum payload length the IUT can support for this alphabet">Payload Length Maximum:</div>
				<input class="fieldInput" type="number" id="payloadmax" name="payloadmax" min="2" max="4294967296" value="2">
			</div>
		`;

		editDisplay.appendChild(fieldWrapper);

		document.getElementById("capabilitiesalphabet").value = algos[algoIndex]["capabilities"]["alphabet"];
		document.getElementById("capabilitiesalphabet").addEventListener("change", () => {
			let alphabet = document.getElementById("capabilitiesalphabet").value;
			const allowedCharacters = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
				"u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R",
				"S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"];
			for (let i=0; i<alphabet.length; i++) {
				if (alphabet.indexOf(alphabet[i]) != i || allowedCharacters.indexOf(alphabet[i]) == -1) {
					alphabet = removeByIndex(alphabet, i);
					i--;
				}
			}
			document.getElementById("capabilitiesalphabet").value = alphabet;
			algos[algoIndex]["capabilities"]["alphabet"] = alphabet;
			algos[algoIndex]["capabilities"]["radix"] = alphabet.length;
			document.getElementById("payloadmin").dispatchEvent(new Event("change"));
			document.getElementById("payloadmax").dispatchEvent(new Event("change"));
			updateVrfDisplay();
		});

		document.getElementById("payloadmin").value = algos[algoIndex]["capabilities"]["minLen"];
		document.getElementById("payloadmin").addEventListener("change", () => {
			let newMin = parseInt(document.getElementById("payloadmin").value);
			if (Math.pow(algos[algoIndex]["capabilities"]["alphabet"].length, newMin) < 1000000) {
				newMin = Math.ceil(Math.log(1000000) / Math.log(algos[algoIndex]["capabilities"]["alphabet"].length));
				document.getElementById("payloadmin").value = newMin;
			} else if (newMin > parseInt(document.getElementById("payloadmax").value)) {
				newMin = parseInt(document.getElementById("payloadmax").value);
				document.getElementById("payloadmin").value = newMin;
			}
			algos[algoIndex]["capabilities"]["minLen"] = newMin;
			updateVrfDisplay();
		});

		document.getElementById("payloadmax").value = algos[algoIndex]["capabilities"]["maxLen"];
		document.getElementById("payloadmax").addEventListener("change", () => {
			let newMax = parseInt(document.getElementById("payloadmax").value);
			if (newMax < parseInt(document.getElementById("payloadmin").value)) {
				newMax = parseInt(document.getElementById("payloadmin").value);
				document.getElementById("payloadmax").value = newMax;
			}
			algos[algoIndex]["capabilities"]["maxLen"] = newMax;
			updateVrfDisplay();
		});
	} else if (ACVPalgos[currentAlgo] == "cSHAKE-128" || ACVPalgos[currentAlgo] == "cSHAKE-256") {
		createBooleanLink(algos[algoIndex], "hexCustomization", "Hex Customization", "An optional feature to the implementation. When true, \"hex\" customization strings are supported, otherwise they aren't. ASCII strings SHALL be tested regardless of the value within the hex customization property");
		createLengthLink(algos[algoIndex], "msgLen", "Message Length", "Input length of the extendable-output function, in bits", 0, 65536, true);
		createLengthLink(algos[algoIndex], "outputLen", "Output Length", "Output length of the extendable-output function, in bits", 16, 65536, true);
	} else if (ACVPalgos[currentAlgo] == "KMAC-128" || ACVPalgos[currentAlgo] == "KMAC-256") {
		createOptionLink(algos[algoIndex], "xof", "XOF algorithms", "Implementation has the ability to act as an extendable-output function (XOF) or non-XOF algorithm", [["XOF", true], ["non-XOF", false]], true);
		createBooleanLink(algos[algoIndex], "hexCustomization", "Hex Customization", "An optional feature to the implementation. When true, \"hex\" customization strings are supported, otherwise they aren't. ASCII strings SHALL be tested regardless of the value within the hex customization property");
		createLengthLink(algos[algoIndex], "msgLen", "Message Length", "Input length of the extendable-output function, in bits", 0, 65536, true);
		createLengthLink(algos[algoIndex], "outputLen", "Output Length", "Output length of the extendable-output function, in bits", 0, 65536, true);
		createLengthLink(algos[algoIndex], "keyLen", "Key Length", "Supported key lengths, in bits", 128, 524288, false);
		createLengthLink(algos[algoIndex], "macLen", "MAC Length", "Supported message authentication code lengths, in bits", 32, 65536, false);
	} else if (ACVPalgos[currentAlgo] == "ParallelHash-128" || ACVPalgos[currentAlgo] == "ParallelHash-256") {
		createOptionLink(algos[algoIndex], "xof", "XOF algorithms", "Implementation has the ability to act as an extendable-output function (XOF) or non-XOF algorithm", [["XOF", true], ["non-XOF", false]], true);
		createBooleanLink(algos[algoIndex], "hexCustomization", "Hex Customization", "An optional feature to the implementation. When true, \"hex\" customization strings are supported, otherwise they aren't. ASCII strings SHALL be tested regardless of the value within the hex customization property");
		createLengthLink(algos[algoIndex], "msgLen", "Message Length", "Input length of the extendable-output function, in bits", 0, 65536, true);
		createLengthLink(algos[algoIndex], "outputLen", "Output Length", "Output length of the extendable-output function, in bits", 0, 65536, true);
		createLengthLink(algos[algoIndex], "blockSize", "Block Size", "Block size, in bytes", 1, 128, false);
	} else if (ACVPalgos[currentAlgo] == "TupleHash-128" || ACVPalgos[currentAlgo] == "TupleHash-256") {
		createOptionLink(algos[algoIndex], "xof", "XOF algorithms", "Implementation has the ability to act as an extendable-output function (XOF) or non-XOF algorithm", [["XOF", true], ["non-XOF", false]], true);
		createBooleanLink(algos[algoIndex], "hexCustomization", "Hex Customization", "An optional feature to the implementation. When true, \"hex\" customization strings are supported, otherwise they aren't. ASCII strings SHALL be tested regardless of the value within the hex customization property");
		createLengthLink(algos[algoIndex], "msgLen", "Message Length", "Input length of the extendable-output function, in bits", 0, 65536, true);
		createLengthLink(algos[algoIndex], "outputLen", "Output Length", "Output length of the extendable-output function, in bits", 16, 65536, true);
	} else if (ACVPalgos[currentAlgo] == "CMAC-AES") {
		createOptionLink(algos[algoIndex]["capabilities"][0], "direction", "Direction", "Generation will proceed with normally running the randomly chosen key and message data through the MAC algorithm. Verification can successfully determine when a MAC does not match its originating message/key combination", [["Generation", "gen"], ["Verification", "ver"]], true);
		createOptionLink(algos[algoIndex]["capabilities"][0], "keyLen", "Key Length", "Supported key lengths, in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createLengthLink(algos[algoIndex]["capabilities"][0], "msgLen", "Message Length", "Supported message lengths, in bits", 0, 524288, false);
		createLengthLink(algos[algoIndex]["capabilities"][0], "macLen", "MAC Length", "Supported output sizes, in bits", 1, 128, true);
	} else if (ACVPalgos[currentAlgo] == "CMAC-TDES") {
		createOptionLink(algos[algoIndex]["capabilities"][0], "direction", "Direction", "Generation will proceed with normally running the randomly chosen key and message data through the MAC algorithm. Verification can successfully determine when a MAC does not match its originating message/key combination", [["Generation", "gen"], ["Verification", "ver"]], true);
		createOptionLink(algos[algoIndex], "keyingOption", "Keying Option", "The keying option used in TDES. Option 1 is for 3 distinct keys, option 2 is for 2 distinct keys. NOTE: option 2 is only allowed for decrypt", [["1", 1], ["2", 2]], true);
		createLengthLink(algos[algoIndex]["capabilities"][0], "msgLen", "Message Length", "Supported message lengths, in bits", 0, 524288, false);
		createLengthLink(algos[algoIndex]["capabilities"][0], "macLen", "MAC Length", "Supported output sizes, in bits", 32, 64, true);
	} else if (ACVPalgos[currentAlgo] == "ACVP-AES-GMAC") {
		createOptionLink(algos[algoIndex], "direction", "Direction", "The IUT processing direction", [["Encrypt", "encrypt"], ["Decrypt", "decrypt"]], true);
		createOptionLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", [["128", 128], ["192", 192], ["256", 256]], true);
		createLengthLink(algos[algoIndex], "ivLen", "IV Length", "The supported initialization vector/nonce lengths in bits", 8, 1024, false);
		createOptionLink(algos[algoIndex], "ivGen", "IV Generation", "The method of generating initialization vectors. Internal if and only if generation is done within the cryptographic module", [["Internal", "internal"], ["External", "external"]], false);
		createOptionLink(algos[algoIndex], "ivGenMode", "IV Generation Mode", "Which initialization vector construction method the implementation conforms to as defined in SP 800-38D. The value represents the section number of the definition -- 8.2.1 is deterministic and 8.2.2 is RBG-based", [["8.2.1", "8.2.1"], ["8.2.2", "8.2.2"]], false);
		createLengthLink(algos[algoIndex], "aadLen", "AAD Length", "The length of additional authenticated data to use, in bits", 0, 65536, false);
		createOptionLink(algos[algoIndex], "tagLen", "Tag Length", "The supported lengths of authentication tag for authenticated encryption with associated data (AEAD), in bits", [["32", 32], ["64", 64], ["96", 96], ["104", 104], ["112", 112], ["120", 120], ["128", 128]], true);
	} else if (group4.indexOf(ACVPalgos[currentAlgo]) != -1) {
		createLengthLink(algos[algoIndex], "keyLen", "Key Length", "The supported key lengths in bits", 8, 524288, false);
		createLengthLink(algos[algoIndex], "macLen", "MAC Length", "The supported mac sizes, in bits", 32, maxMACLengths[algoIndex - 53], true);
	} else if (ACVPalgos[currentAlgo] == "safePrimes") {
		createOptionLink(algos[algoIndex], "mode", "Mode", "The SafePrimes mode to be validated", [["Key Generation", "keyGen"], ["Key Verification", "keyVer"]], false);
		createOptionLink(algos[algoIndex], "safePrimeGroups", "Groups", "Safe prime groups to test with", [["MODP-2048", "MODP-2048"], ["MODP-3072", "MODP-3072"], ["MODP-4096", "MODP-4096"], ["MODP-6144", "MODP-6144"], ["MODP-8192", "MODP-8192"], ["ffdhe2048", "ffdhe2048"], ["ffdhe3072", "ffdhe3072"], ["ffdhe4096", "ffdhe4096"], ["ffdhe6144", "ffdhe6144"], ["ffdhe8192", "ffdhe8192"]], true, true);
	} else if (ACVPalgos[currentAlgo] == "ikev1" || ACVPalgos[currentAlgo] == "ikev2") {
		createOptionLink(algos[algoIndex]["capabilities"][0], "authenticationMethod", "Authentication Method", "The mode of authentication used by the IUT", [["DSA", "dsa"], ["Pre-shared key", "psk"], ["PKE", "pke"]], true);
		createLengthLink(algos[algoIndex]["capabilities"][0], "initiatorNonceLength", "Initiator Nonce Length", "The supported initiator nonce lengths used by the IUT in bits", 64, 2048, false); 
		createLengthLink(algos[algoIndex]["capabilities"][0], "responderNonceLength", "Responder Nonce Length", "The lengths of data the IUT supports in bits", 64, 2048, false);
		createLengthLink(algos[algoIndex]["capabilities"][0], "diffieHellmanSharedSecretLength", "Diffie-Hellman Shared Secret Length", "The lengths of Diffie Hellman shared secrets the IUT supports in bits", 224, 8192, false);
		createLengthLink(algos[algoIndex]["capabilities"][0], "preSharedKeyLength", "Pre-shared Key Length", "The lengths of pre-shared key the IUT supports in bits", 8, 8192, false);
		createOptionLink(algos[algoIndex]["capabilities"][0], "hashAlg", "Hash Algorithm", "Valid hash algorithms used by the IUT", [["SHA-1", "sha-1"], ["SHA2-224", "sha2-224"], ["SHA2-256", "sha2-256"], ["SHA2-384", "sha2-384"], ["SHA2-512", "sha2-512"]], true);
	} else if (ACVPalgos[currentAlgo] == "tls") {
		createOptionLink(algos[algoIndex], "tlsVersion", "TLS Version", "The version of TLS supported	", [["v1.0/v1.1", "v1.0/v1.1"], ["v1.2", "v1.2"]], true);
		createOptionLink(algos[algoIndex], "hashAlg", "Hash Algorithm", "SHA functions supported if TLS Version \"v1.2\" is included in the registration", [["SHA2-256", "SHA2-256"], ["SHA2-384", "SHA2-384"], ["SHA2-512", "SHA2-512"]], true);
	} else if (ACVPalgos[currentAlgo] == "signaturePrimitive") {
		createOptionLink(algos[algoIndex], "pubExpMode", "Public Exponent Mode", "Whether the IUT can handle a random or fixed public exponent", [], false);
		createOptionLink(algos[algoIndex], "keyFormat", "Key Format", "The format by which the client expects the private key to be communicated. Standard refers to the default p, q, d values. Chinese Remainder Theorem uses decomposed values for optimized decryption p, q, dmp1, dmq1, iqmp
	} else if (ACVPalgos[currentAlgo] == "decryptionPrimitive") {

	}

	updateScreenHeight();
}

function removeAlgo (algoID) {
	for (let i=0; i<algos.length; i++) {
		if (algos[i]["algorithm"] == ACVPalgos[algoID]) {
			algos.splice(i, 1);
		}
	}
	algoContent2.removeChild(document.getElementById(algoID));
	updateVrfDisplay();
}

function editAlgo (algoID) {
	if (!document.getElementById(algoID)) {
		if (currentAlgo == algoID) {
			editDisplay.classList.remove("show");
			updateScreenHeight();
		}
		return;
	}
	if (currentAlgo == algoID) {
		editDisplay.classList.toggle("show");
	} else {
		editDisplay.classList.add("show");
	}
	updateScreenHeight();
	if (editDisplay.classList.contains("show")) {
		for (let child of algoContent2.children) {
			child.style.border = "2px solid black";
		}
		document.getElementById(algoID).style.border = "2px solid white";
	} else {
		document.getElementById(algoID).style.border = "2px solid black";
	}

	currentAlgo = algoID;
	updateEditDisplay();
}

function addAlgo (algoID, isNew) {
	if (isNew) {
		searchInput.value = "";
		let a = dropdown.getElementsByTagName("a");
		for (let i = 0; i < a.length; i++) {
			a[i].style.display = "";
		}
		dropdown.classList.toggle("show");
	}

	let algoElement = document.createElement("div");
	if (algoID >= 13 && algoID <= 44 || algoID == 66) {
		//ACVP symmetric
		algoElement.textContent = ACVPalgos[algoID].substring(5);
	} else if (algoID == 67) {
		algoElement.textContent = "Safe Primes";
	} else if (ACVPalgos[currentAlgo] == "ikev1") {
		algoElement.textContent = "IKEv1";
	} else if (ACVPalgos[currentAlgo] == "ikev2") {
		algoElement.textContent = "IKEv2";
	} else if (ACVPalgos[currentAlgo] == "tls") {
		algoElement.textContent = "TLS";
	} else if (ACVPalgos[currentAlgo] == "signaturePrimitive") {
		algoElement.textContent = "RSA Signature Primitive";
	} else if (ACVPalgos[currentAlgo] == "decryptionPrimitive") {
		algoElement.textContent = "RSA Decryption Primitive";
	} else {
		algoElement.textContent = ACVPalgos[algoID];
	}
	algoElement.classList.add("algoElement");
	if (algoID < 11) {
		algoElement.style.backgroundColor = "#FF0000";
	} else if (algoID < 13 || ACVPalgos[algoID] == "cSHAKE-128" || ACVPalgos[algoID] == "cSHAKE-256" || ACVPalgos[algoID] == "ParallelHash-128" || ACVPalgos[algoID] == "ParallelHash-256" || ACVPalgos[algoID] == "TupleHash-128" || ACVPalgos[algoID] == "TupleHash-256") {
		algoElement.style.backgroundColor = "#EE0055";
	} else if (group1.indexOf(ACVPalgos[algoID]) != -1 || group3.indexOf(ACVPalgos[algoID]) != -1 || ACVPalgos[algoID] == "ACVP-AES-FF3-1" || ACVPalgos[algoID] == "ACVP-AES-FF1" || ACVPalgos[algoID] == "ACVP-AES-CTR" || ACVPalgos[algoID] == "ACVP-AES-KW" || ACVPalgos[algoID] == "ACVP-AES-KWP" || ACVPalgos[algoID] == "ACVP-AES-GCM" || ACVPalgos[algoID] == "ACVP-AES-GCM-SIV" || ACVPalgos[algoID] == "ACVP-AES-XPN" || ACVPalgos[algoID] == "ACVP-AES-XTS" || ACVPalgos[algoID] == "ACVP-AES-GMAC") {
		algoElement.style.backgroundColor = "#00DD00";
	} else if (group2.indexOf(ACVPalgos[algoID]) != -1 || ACVPalgos[algoID] == "ACVP-TDES-KW" || ACVPalgos[algoID] == "ACVP-TDES-CTR") {
		algoElement.style.backgroundColor = "#88FF00";
	} else if (ACVPalgos[algoID] == "KMAC-128" || ACVPalgos[algoID] == "KMAC-256") {
		algoElement.style.background = "linear-gradient(to bottom right, #EE0055 0 30%, #FFFF00 70% 100%)";
	} else if (ACVPalgos[algoID] == "ACVP-AES-CCM" || ACVPalgos[algoID] == "CMAC-AES") {
		algoElement.style.background = "linear-gradient(to bottom right, #00DD00 0 30%, #FFFF00 70% 100%)";
	} else if (ACVPalgos[algoID] == "CMAC-TDES") {
		algoElement.style.background = "linear-gradient(to bottom right, #88FF00 0 30%, #FFFF00 70% 100%)";
	} else if (group4.indexOf(ACVPalgos[algoID]) != -1) {
		algoElement.style.backgroundColor = "#FFFF00";
	} else if (ACVPalgos[algoID] == "safePrimes") {
		algoElement.style.backgroundColor = "#a87332";
	} else if (ACVPalgos[algoID] == "ikev1" || ACVPalgos[algoID] == "ikev2" || ACVPalgos[algoID] == "tls") {
		algoElement.style.backgroundColor = "#42f5f2";
	} else if (ACVPalgos[algoID] == "signaturePrimitive" || ACVPalgos[algoID] == "decryptionPrimitive") {
		algoElement.style.backgroundColor = "#040ac4";
	}
	algoElement.id = algoID;
	algoElement.addEventListener("click", () => {
		editAlgo(algoID);
	});

	let algoClose = document.createElement("img");
	algoClose.src = "/delete.png";
	algoClose.classList.add("closeElement");
	algoClose.addEventListener("click", () => {
		removeAlgo(algoID);
	});

	algoContent2.appendChild(algoElement);

	const maxFontSize = 16;
	for (let i=maxFontSize; i>1; i--) {
		algoElement.style.fontSize = i + 'px';
		if (!checkOverflow(algoElement)) {
			break;
		}
	}
	algoElement.appendChild(algoClose);

	let newAlgoObject;
	if (algoID < 11) {
		//SHA1 & 2
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"messageLength": [{
				"min": 0,
				"max": 65535,
				"increment": 8
			}],
			"performLargeDataTest": []
		};
		if (algoID >= 7) {
			//SHA3
			newAlgoObject["revision"] = "2.0";
		}
	} else if (algoID < 13) {
		//SHAKE
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"inBit": true,
			"inEmpty": true,
			"outBit": true,
			"outputLen": [{
				"min": 16,
				"max": 1024
			}]
		};
	} else if (group1.indexOf(ACVPalgos[algoID]) != -1) {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": []
		};
	} else if (group2.indexOf(ACVPalgos[algoID]) != -1) {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyingOption": []
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-KW") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"kwCipher": [],
			"payloadLen": [{
				"min": 128,
				"max": 4096,
				"increment": 64
			}]
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-KWP") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"kwCipher": [],
			"payloadLen": [{
				"min": 8,
				"max": 4096,
				"increment": 8
			}]
		};
	} else if (ACVPalgos[algoID] == "ACVP-TDES-KW") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"kwCipher": [],
			"keyingOption": [],
			"payloadLen": [{
				"min": 64,
				"max": 4096,
				"increment": 32
			}]
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-GCM") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"payloadLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"ivLen": [{
				"min": 8,
				"max": 1024,
				"increment": 1
			}],
			"ivGen": "",
			"ivGenMode": "",
			"aadLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"tagLen": []
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-GCM-SIV") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"payloadLen": [{
				"min": 0,
				"max": 65536,
				"increment": 8
			}],
			"aadLen": [{
				"min": 0,
				"max": 65536,
				"increment": 8
			}]
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-XPN") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"payloadLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"ivGen": "",
			"ivGenMode": "",
			"saltGen": "",
			"aadLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"tagLen": []
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-CCM") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"payloadLen": [{
				"min": 0,
				"max": 256,
				"increment": 8
			}],
			"ivLen": [{
				"min": 56,
				"max": 104,
				"increment": 8
			}],
			"aadLen": [{
				"min": 0,
				"max": 524288,
				"increment": 1
			}],
			"tagLen": []
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-XTS") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "2.0",
			"direction": [],
			"keyLen": [],
			"payloadLen": [{
				"min": 128,
				"max": 65536,
				"increment": 8
			}],
			"tweakMode": [],
			"dataUnitLenMatchesPayload": true
		};
	} else if (group3.indexOf(ACVPalgos[algoID]) != -1) {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"payloadLen": [{
				"min": 128,
				"max": 65536,
				"increment": 1
			}]
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-CTR") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"conformances": [],
			"direction": [],
			"keyLen": [],
			"payloadLen": [{
				"min": 1,
				"max": 128,
				"increment": 1
			}],
			"overflowCounter": false,
			"incrementalCounter": true,
			"performCounterTests": false
		};
	} else if (ACVPalgos[algoID] == "ACVP-TDES-CTR") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"conformances": [],
			"direction": [],
			"payloadLen": [{
				"min": 1,
				"max": 64,
				"increment": 1
			}],
			"keyingOption": [],
			"overflowCounter": false,
			"incrementalCounter": true,
			"performCounterTests": false
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-FF1") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"tweakLen": [{
				"min": 0,
				"max": 128,
				"increment": 8
			}],
			"capabilities": {
				"alphabet": "abcdefghijklmnop12345",
				"radix": 21,
				"minLen": 5,
				"maxLen": 4294967296
			}
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-FF3-1") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"capabilities": {
				"alphabet": "abcdefghijklmnop12345",
				"radix": 21,
				"minLen": 5,
				"maxLen": 4294967296
			}
		};
	} else if (ACVPalgos[algoID] == "cSHAKE-128" || ACVPalgos[algoID] == "cSHAKE-256") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"hexCustomization": false,
			"msgLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"outputLen": [{
				"min": 16,
				"max": 65536,
				"increment": 1
			}]
		};
	} else if (ACVPalgos[algoID] == "KMAC-128" || ACVPalgos[algoID] == "KMAC-256") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"hexCustomization": false,
			"xof": [],
			"msgLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"outputLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"keyLen": [{
				"min": 128,
				"max": 524288,
				"increment": 8
			}],
			"macLen": [{
				"min": 32,
				"max": 65536,
				"increment": 8
			}]
		};
	} else if (ACVPalgos[algoID] == "ParallelHash-128" || ACVPalgos[algoID] == "ParallelHash-256") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"hexCustomization": false,
			"xof": [],
			"msgLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"outputLen": [{
				"min": 16,
				"max": 65536,
				"increment": 1
			}],
			"blockSize": [{
				"min": 1,
				"max": 128,
				"increment": 1
			}]
		};
	} else if (ACVPalgos[algoID] == "TupleHash-128" || ACVPalgos[algoID] == "TupleHash-256") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"hexCustomization": false,
			"xof": [],
			"msgLen": [{
				"min": 0,
				"max": 65536,
				"increment": 1
			}],
			"outputLen": [{
				"min": 16,
				"max": 65536,
				"increment": 1
			}]
		};
	} else if (ACVPalgos[algoID] == "CMAC-AES") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"capabilities": [{
				"direction": [],
				"keyLen": [],
				"msgLen": [{
					"min": 0,
					"max": 524288,
					"increment": 8
				}],
				"macLen": [{
					"min": 1,
					"max": 128,
					"increment": 1
				}]
			}]
		};
	} else if (ACVPalgos[algoID] == "CMAC-TDES") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"capabilities": [{
				"direction": [],
				"keyingOption": [],
				"msgLen": [{
					"min": 0,
					"max": 524288,
					"increment": 8
				}],
				"macLen": [{
					"min": 32,
					"max": 64,
					"increment": 1
				}]
			}]
		};
	} else if (ACVPalgos[algoID] == "ACVP-AES-GMAC") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"direction": [],
			"keyLen": [],
			"ivLen": [{
				"min": 8,
				"max": 1024,
				"increment": 8
			}],
			"ivGen": "",
			"ivGenMode": "",
			"aadLen": [{
				"min": 0,
				"max": 65536,
				"increment": 8
			}],
			"tagLen": []
		};
	} else if (group4.indexOf(ACVPalgos[algoID]) != -1) {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"keyLen": [{
				"min": 8,
				"max": 524288,
				"increment": 8
			}],
			"macLen": [{
				"min": 32,
				"max": maxMACLengths[algoID - 53],
				"increment": 1
			}]
		};
	} else if (ACVPalgos[algoID] == "safePrimes") {
		newAlgoObject = {
			"algorithm": ACVPalgos[algoID],
			"revision": "1.0",
			"mode": "keyVer",
			"safePrimeGroups": ["MODP-2048"]
		};
	} else if (ACVPalgos[algoID] == "ikev1" || ACVPalgos[algoID] == "ikev2") {
		newAlgoObject = {
			"algorithm": "kdf-components",
			"mode": ACVPalgos[algoID],
			"revision": "1.0",
			"capabilities": [{
				"authenticationMethod": "",
				"initiatorNonceLength": [{
					"min": 64,
					"max": 2048,
					"increment": 1
				}],
				"responderNonceLength": [{
					"min": 64,
					"max": 2048,
					"increment": 1
				}],
				"diffieHellmanSharedSecretLength": [{
					"min": 224,
					"max": 8192,
					"increment": 1
				}],
				"preSharedKeyLength": [{
					"min": 8,
					"max": 8192,
					"increment": 1
				}],
				"hashAlg": []
			}]
		};
	} else if (ACVPalgos[algoID] == "tls") {
		newAlgoObject = {
			"algorithm": "kdf-components",
			"mode": "tls",
			"revision": "1.0",
			"tlsVersion": [],
			"hashAlg": []
		};
	} else if (ACVPalgos[algoID] == "signaturePrimitive" || ACVPalgos[algoID] == "decryptionPrimitive") {
		newAlgoObject = {
			"algorithm": "RSA",
			"mode": ACVPalgos[algoID],
			"revision": "2.0",
			"isSample": true,
			"pubExpMode": "fixed",
			"fixedPubExp": "",
			"keyFormat": [],
			"modulus": []
		};
	}

	if (isNew) {
		algos.push(Object.assign({}, newAlgoObject));
	}

	updateVrfDisplay();
}

for (let i=0; i<ACVPalgos.length; i++) {
	let algoItem = document.createElement("a");
	algoItem.addEventListener("click", () => {
		addAlgo(i, true);
	});
	if (i >= 13 && i <= 44 || i == 66) {
		algoItem.textContent = ACVPalgos[i].substring(5);
	} else {
		algoItem.textContent = ACVPalgos[i];
	}
	dropdownElements.appendChild(algoItem);
}

function filterFunction () {
	let filter = searchInput.value.toUpperCase();
	let a = dropdown.getElementsByTagName("a");
	for (let i = 0; i < a.length; i++) {
		txtValue = a[i].textContent || a[i].innerText;
		if (txtValue.toUpperCase().indexOf(filter) > -1) {
			a[i].style.display = "";
		} else {
			a[i].style.display = "none";
		}
	}
}

function createLengthLink (linkLocation, id, fieldTitle, fieldDescription, lengthMin, lengthMax, hasIncrement) {
	editDisplay.appendChild(createLengthField(id, fieldTitle, fieldDescription, lengthMin, lengthMax, hasIncrement));
	document.getElementById(`${id}min`).value = linkLocation[`${id}`][0]["min"];
	document.getElementById(`${id}max`).value = linkLocation[`${id}`][0]["max"];
	document.getElementById(`${id}min`).addEventListener("change", () => {
		let newMin = parseInt(document.getElementById(`${id}min`).value);
		if (newMin > parseInt(document.getElementById(`${id}max`).value)) {
			newMin = parseInt(document.getElementById(`${id}max`).value);
			document.getElementById(`${id}min`).value = newMin;
		}
		linkLocation[`${id}`][0]["min"] = newMin;
		updateVrfDisplay();
	});
	document.getElementById(`${id}max`).addEventListener("change", () => {
		let newMax = parseInt(document.getElementById(`${id}max`).value);
		if (newMax < parseInt(document.getElementById(`${id}min`).value)) {
			newMax = parseInt(document.getElementById(`${id}min`).value);
			document.getElementById(`${id}max`).value = newMax;
		}
		linkLocation[`${id}`][0]["max"] = newMax;
		updateVrfDisplay();
	});
	if (hasIncrement) {
		document.getElementById(`${id}inc`).value = linkLocation[`${id}`][0]["increment"];
		document.getElementById(`${id}inc`).addEventListener("change", () => {
			linkLocation[`${id}`][0]["increment"] = parseInt(document.getElementById(`${id}inc`).value);
			updateVrfDisplay();
		});
	}
}

function createLengthField (id, fieldTitle, fieldDescription, lengthMin, lengthMax, hasIncrement) {
	let fieldWrapper = document.createElement("div");
	fieldWrapper.id = id;
	fieldWrapper.classList.add("fieldWrapper");

	fieldWrapper.innerHTML = `
		<div class="inputWrapper">
			<div class="fieldLabel" title="${fieldDescription}">${fieldTitle} Minimum:</div>
			<input class="fieldInput" type="number" id="${id}min" name="${id}min" min="${lengthMin}" max="${lengthMax}" value="${lengthMin}">
		</div>
		<div class="inputWrapper">
			<div class="fieldLabel" title="${fieldDescription}">${fieldTitle} Maximum:</div>
			<input class="fieldInput" type="number" id="${id}max" name="${id}max" min="${lengthMin}" max="${lengthMax}" value="${lengthMax}">
		</div>
	`;

	if (hasIncrement) {
		let incrementWrapper = document.createElement("div");
		incrementWrapper.classList.add("inputWrapper");

		let incrementLabel = document.createElement("div");
		incrementLabel.textContent = `${fieldTitle} Increment:`;
		incrementLabel.title = `${fieldDescription}`;
		incrementLabel.classList.add("fieldLabel");

		let incrementInput = document.createElement("input");
		incrementInput.classList.add("fieldInput");
		incrementInput.type = "number";
		incrementInput.id = `${id}inc`;
		incrementInput.name = `${id}inc`;
		incrementInput.min = "1";
		incrementInput.max = `${lengthMax}`;
		incrementInput.value = "8";

		incrementWrapper.appendChild(incrementLabel);
		incrementWrapper.appendChild(incrementInput);
		fieldWrapper.appendChild(incrementWrapper);
	}

	return fieldWrapper;
}

function createOptionLink (linkLocation, id, fieldTitle, fieldDescription, optionList, multiple, nonempty = false) {
	editDisplay.appendChild(createOptionField(id, fieldTitle, fieldDescription, optionList, multiple));
	if (multiple) {
		for (let i=0; i<linkLocation[`${id}`].length; i++) {
			let optionNum = linkLocation[`${id}`][i];
			document.getElementById(`${id}option${optionNum}`).selected = true;
		}
		document.getElementById(`${id}`).addEventListener("change", () => {
			linkLocation[`${id}`] = [];
			let valueArray = [];
			for (let i=0; i<optionList.length; i++) {
				valueArray.push(optionList[i][1]);
			}
			let numSelected = 0;
			for (let i=0; i<valueArray.length; i++) {
				if (document.getElementById(`${id}option${valueArray[i]}`).selected == true) {
					linkLocation[`${id}`].push(valueArray[i]);
					numSelected++;
				}
			}
			if (nonempty && numSelected == 0) {
				document.getElementById(`${id}option${valueArray[0]}`).selected = true;
				linkLocation[`${id}`].push(valueArray[0]);
			}
			updateVrfDisplay();
		});
	} else {
		for (let i=0; i<optionList.length; i++) {
			if (linkLocation[`${id}`] == optionList[i][1]) {
				document.getElementById(`${id}option${optionList[i][1]}`).selected = true;
			}
		}
		document.getElementById(`${id}`).addEventListener("change", () => {
			for (let i=0; i<optionList.length; i++) {
				if (document.getElementById(`${id}option${optionList[i][1]}`).selected == true) {
					linkLocation[`${id}`] = optionList[i][1];
				}
			}
			updateVrfDisplay();
		});
	}
}

function createOptionField (id, fieldTitle, fieldDescription, optionList, multiple) {
	let fieldWrapper = document.createElement("div");
	fieldWrapper.id = id;
	fieldWrapper.classList.add("fieldWrapper");

	let inputWrapper = document.createElement("div");
	inputWrapper.classList.add("inputWrapper");

	let fieldLabel = document.createElement("div");
	fieldLabel.classList.add("fieldLabel");
	fieldLabel.textContent = `${fieldTitle}:`;
	fieldLabel.title = fieldDescription;

	let optionSelect = document.createElement("select");
	optionSelect.id = `${id}option`;
	optionSelect.classList.add("fieldInput");
	optionSelect.size = Math.min(3, optionList.length);
	if (multiple) {
		optionSelect.setAttribute("multiple", "");
	}
	for (let i=0; i<optionList.length; i++) {
		let optionField = document.createElement("option");
		optionField.id = `${id}option${optionList[i][1]}`;
		optionField.textContent = optionList[i][0];
		optionField.value = optionList[i][1];
		optionSelect.appendChild(optionField);
	}

	inputWrapper.appendChild(fieldLabel);
	inputWrapper.appendChild(optionSelect);
	fieldWrapper.appendChild(inputWrapper);

	return fieldWrapper;
}

function createBooleanLink (linkLocation, id, fieldTitle, fieldDescription) {
	editDisplay.appendChild(createBooleanField(id, fieldTitle, fieldDescription));
	document.getElementById(`${id}box`).checked = linkLocation[`${id}`];
	document.getElementById(`${id}box`).addEventListener("change", () => {
		linkLocation[`${id}`] = document.getElementById(`${id}box`).checked;
		updateVrfDisplay();
	});

}

function createBooleanField (id, fieldTitle, fieldDescription) {
	let fieldWrapper = document.createElement("div");
	fieldWrapper.id = id;
	fieldWrapper.classList.add("fieldWrapper");
	fieldWrapper.classList.add("thinWrapper");

	fieldWrapper.innerHTML = `
		<div class="inputWrapper">
			<div class="fieldLabel" title="${fieldDescription}">${fieldTitle}:</div>
			<input class="fieldInput" type="checkbox" name="${id}box" id="${id}box">
		</div>
	`;

	return fieldWrapper;
}

copyBtn.addEventListener("click", () => {
	copyToClipboard(JSON.stringify(vrf, null, 2));
});

newBtn.addEventListener("click", () => {
	dropdown.classList.toggle("show");
});

downloadBtn.addEventListener("click", () => {
	let filename = "";
	for (let i=0; i<algos.length; i++) {
		filename += algos[i]["algorithm"];
		if (i != algos.length - 1) {
			filename += "_";
		}
	}
	if (filename.length == 0 || filename.length > 100) {
		filename = "capfile";
	}
	downloadObjectAsJson(vrf, filename);
});

let loadFile = document.createElement("input");
loadFile.id = "loadFileInput";
loadFile.className = "button";
loadFile.name = "button";
loadFile.type = "file";

let loadLabel = document.createElement("label");
loadLabel.innerHTML = "Load registration file";
loadLabel.className = "button";

loadLabel.appendChild(loadFile);
extractWrapper.appendChild(loadLabel);

;(function(){
	function onChange (event) {
		let reader = new FileReader();
		reader.onload = onReaderLoad;
		reader.readAsText(event.target.files[0]);
	}

	$("#loadFileInput").on("click touchstart", function () {
		$(this).val("");
	});

	function onReaderLoad (event) {
		let newVrf;
		try {
			newVrf = JSON.parse(event.target.result);
		} catch (err) {
			alert("Error reading capabilities file");
			return;
		}
		let isValid = false;
		for (let i=0; i<newVrf.length; i++) {
			if (newVrf[i]["algos"]) {
				isValid = true;
				removeAllChildNodes(algoContent2);
				removeAllChildNodes(editDisplay);
				editDisplay.classList.remove("show");
				updateScreenHeight();
				for (let j=0; j<newVrf[i]["algos"].length; j++) {
					if (ACVPalgos.indexOf(newVrf[i]["algos"][j]["algorithm"]) != -1) {
						addAlgo(ACVPalgos.indexOf(newVrf[i]["algos"][j]["algorithm"]), false);
					}
				}
			}
		}
		if (isValid) {
			vrf = newVrf;
			updateVrfDisplay();
		} else {
			alert("Error reading capabilities file");
		}
	}

	document.getElementById("loadFileInput").addEventListener("change", onChange);
}());

algorithmsMinimize.addEventListener("click", () => {
	if (algoDisplay.style.height == "5vh") {
		algoDisplay.style.height = "40vh";
		algoContent1.style.display = "flex";
		algoContent2.style.display = "flex";
		algoContent3.style.display = "block";
		algorithmsMinimize.src = "/minimize.png";
		updateScreenHeight();
	} else {
		algoDisplay.style.height = "5vh";
		algoContent1.style.display = "none";
		algoContent2.style.display = "none";
		algoContent3.style.display = "none";
		algorithmsMinimize.src = "/maximize.png";
		updateScreenHeight();
	}
});

outputMinimize.addEventListener("click", () => {
	if (outputWrapper.style.height == "5vh") {
		outputWrapper.style.height = "40vh";
		vrfDisplay.style.display = "block";
		outputMinimize.src = "/minimize.png";
		updateScreenHeight();
	} else {
		outputWrapper.style.height = "5vh";
		vrfDisplay.style.display = "none";
		outputMinimize.src = "/maximize.png";
		updateScreenHeight();
	}
});
