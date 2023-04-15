import {
  SmartContract,
  isReady,
  Poseidon,
  Field,
  Permissions,
  State,
  state,
  CircuitValue,
  prop,
  Mina,
  method,
  PrivateKey,
  AccountUpdate,
  MerkleTree,
  MerkleWitness,
  shutdown,
  CircuitString,
} from 'snarkyjs';

await isReady;

const doProofs = true;

class MyMerkleWitness extends MerkleWitness(8) {}

class Record extends CircuitValue {
  @prop status: CircuitString;

  constructor(status: CircuitString) {
    super(status);
    this.status = status;
  }

  hash(): Field {
    return Poseidon.hash(this.toFields());
  }
}

// initiate tree root in order to tell the contract about our off-chain storage
let initialCommitment: Field = Field(0);
/*
      A smart contract that confirms a vendor's credentials.
    */

class VendorCredential extends SmartContract {
  // a commitment is a cryptographic primitive that allows us to commit to data, with the ability to "reveal" it later
  @state(Field) commitment = State<Field>();

  init() {
    super.init();
    this.account.permissions.set({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
    });
    this.commitment.set(initialCommitment);
  }

  @method
  verifyCredential(credentialData: Record, path: MyMerkleWitness) {
    // gets the current root of the tree
    // const root = Tree.getRoot();
    // fetch the on-chain commitment
    let commitment = this.commitment.get();
    this.commitment.assertEquals(commitment);

    // calculates the root of the witness
    let credentialDataHash = credentialData.hash();
    const calculatedRoot = path.calculateRoot(credentialDataHash);

    // Confirm the credential is committed to the Merkle Tree
    calculatedRoot.assertEquals(commitment);
  }
}

// Example field of Vendor Credentialing data
// - Address
// - Social Security Number
// - Vendor Credential e.g. immunization records
// - Vendor Credential e.g. background check
type VendorData = 'Address' | 'SSN' | 'VC01' | 'VC02';

let Local = Mina.LocalBlockchain({ proofsEnabled: doProofs });
Mina.setActiveInstance(Local);
let initialBalance = 10_000_000_000;

let feePayerKey = Local.testAccounts[0].privateKey;
let feePayer = Local.testAccounts[0].publicKey;

// *****************************************************************

// The following Map serves as an off-chain in-memory storage
let Records: Map<string, Record> = new Map<VendorData, Record>();

// Create example credential records
let address = new Record(CircuitString.fromString('1234 Main St'));
let ssn = new Record(CircuitString.fromString('999775555'));
let vc01 = new Record(CircuitString.fromString('Private immunizations'));
let vc02 = new Record(CircuitString.fromString('Background check details'));

Records.set('Address', address);
Records.set('SSN', ssn);
Records.set('VC01', vc01);
Records.set('VC02', vc02);

// "wrap" the Merkle tree around our off-chain storage
// initialize a new Merkle Tree with height 8
const Tree = new MerkleTree(8);

Tree.setLeaf(0n, address.hash());
Tree.setLeaf(1n, ssn.hash());
Tree.setLeaf(2n, vc01.hash());
Tree.setLeaf(3n, vc02.hash());

// Generate a commitment before deploying our contract
initialCommitment = Tree.getRoot();

console.log('Initial Commitment:');
console.log(initialCommitment.toString());

// ***********************************************************

// Deploy smart contract
console.log('Deploying Vendor Credential smart contract..');

// the zkapp record
console.log('Generating a public key to deploy smart contract...');
let zkappKey = PrivateKey.random();
console.log('zkappKey:');
console.log(zkappKey.toBase58());
let zkappAddress = zkappKey.toPublicKey();

let VendorCredentialZkApp = new VendorCredential(zkappAddress);
if (doProofs) {
  await VendorCredential.compile();
}
let tx = await Mina.transaction(feePayer, () => {
  AccountUpdate.fundNewAccount(feePayer).send({
    to: zkappAddress,
    amount: initialBalance,
  });
  VendorCredentialZkApp.deploy();
});
await tx.sign([feePayerKey, zkappKey]).send();

console.log('VendorCredentialZkApp.commitment.get()');
console.log(VendorCredentialZkApp.commitment.get().toString());

let verifyAddress = new Record(CircuitString.fromString('1234 Main St'));
let verifySSN = new Record(CircuitString.fromString('999775555'));
let verifyVC01 = new Record(CircuitString.fromString('Private immunizations'));
let verifyVC02 = new Record(
  CircuitString.fromString('Background check details')
);

// Request to verify Address...
console.log('Request to verify address');
await verifierRequest(0n, verifyAddress);
// Request to verify SSN...
console.log('Request to verify SSN');
await verifierRequest(1n, verifySSN);
// Request to verify VC01...
console.log('Request to verify vendor data 01');
await verifierRequest(2n, verifyVC01);
// Request to verify VC02...
console.log('Request to verify vendor data 02');
await verifierRequest(3n, verifyVC02);

// Testing a request to verify Address (with incorrect data)...
console.log(
  'Testing a request to verify address with incorrect data. Credential verification should fail.'
);
// The correct address should be 1234 Main St.
let verifyAddressFailTest = new Record(
  CircuitString.fromString('5678 Main St')
);

await verifierRequest(0n, verifyAddressFailTest);

async function verifierRequest(index: bigint, credentialData: Record) {
  // Generate witness for leaf at an index
  let w = Tree.getWitness(index);
  // Create a circuit-compatible witness
  let witness = new MyMerkleWitness(w);

  console.log('Verifier request in process...');
  try {
    // Create transaction to
    let tx = await Mina.transaction(feePayer, () => {
      VendorCredentialZkApp.verifyCredential(credentialData, witness);
    });
    // await tx.prove();
    // await tx.sign([feePayerKey, zkappKey]).send();

    console.log('Credentials verified!');
  } catch (ex: any) {
    console.log(
      'Vendor credential does not match. Credentials are not verified'
    );
  }
}

console.log('Shutting down');

await shutdown();
