import {
  SmartContract,
  isReady,
  Poseidon,
  Field,
  Permissions,
  DeployArgs,
  State,
  state,
  CircuitValue,
  PublicKey,
  UInt64,
  prop,
  Mina,
  method,
  UInt32,
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
    const root = Tree.getRoot();

    // calculates the root of the witness
    let credentialDataHash = credentialData.hash();
    const calculatedRoot = path.calculateRoot(credentialDataHash);

    calculatedRoot.assertEquals(root);
  }
}

type VendorData = 'Address' | 'SSN' | 'VC01' | 'VC02';

let Local = Mina.LocalBlockchain({ proofsEnabled: doProofs });
Mina.setActiveInstance(Local);
let initialBalance = 10_000_000_000;

let feePayerKey = Local.testAccounts[0].privateKey;
let feePayer = Local.testAccounts[0].publicKey;

// the zkapp record
let zkappKey = PrivateKey.fromBase58(
  'EKEcnhmtY6ehzn6jwFVXSjcibzPrWjrHSfQVMgYFuDhhdyampDdX'
);
console.log('zkappKey:');
console.log(zkappKey.toBase58());
let zkappAddress = zkappKey.toPublicKey();

// *****************************************************************
// this map serves as our off-chain in-memory storage
let Records: Map<string, Record> = new Map<VendorData, Record>();

let address = new Record(CircuitString.fromString('1234 Main St'));
let ssn = new Record(CircuitString.fromString('999775555'));
let vc01 = new Record(CircuitString.fromString('MedicalRecord01'));
let vc02 = new Record(CircuitString.fromString('MedicalRecord02'));

Records.set('Address', address);
Records.set('SSN', ssn);
Records.set('VC01', vc01);
Records.set('VC02', vc02);

// we now need "wrap" the Merkle tree around our off-chain storage
// we initialize a new Merkle Tree with height 8
const Tree = new MerkleTree(8);

Tree.setLeaf(0n, address.hash());
Tree.setLeaf(1n, ssn.hash());
Tree.setLeaf(2n, vc01.hash());
Tree.setLeaf(3n, vc02.hash());

// Set up set of records, generate a commitment before deploying our contract!
initialCommitment = Tree.getRoot();

console.log('initialCommitment root:');
console.log(initialCommitment.toString());

// ***********************************************************

let VendorCredentialZkApp = new VendorCredential(zkappAddress);
console.log('Deploying VendorCredential..');
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

console.log('Verifier checking a credential..');
console.log('VendorCredentialZkApp.commitment.get()');
console.log(VendorCredentialZkApp.commitment.get().toString());

let verifyAddress = new Record(CircuitString.fromString('1234 Main St'));
let verifySSN = new Record(CircuitString.fromString('999775555'));
let verifyVC01 = new Record(CircuitString.fromString('MedicalRecord01'));
let verifyVC02 = new Record(CircuitString.fromString('MedicalRecord02'));

// Request to verify Address...
console.log('Request to verify address');
await verifierRequest(0n, verifyAddress);
// Request to verify SSN...
console.log('Request to verify ssn');
await verifierRequest(1n, verifySSN);
// Request to verify VC01...
console.log('Request to verify vc01');
await verifierRequest(2n, verifyVC01);
// Request to verify VC02...
console.log('Request to verify vc02');
await verifierRequest(3n, verifyVC02);

// Request to verify Address (with incorrect data)...
console.log(
  'Request to verify address with incorrect data. Credential verification should fail.'
);
let verifyAddressFailTest = new Record(
  CircuitString.fromString('5678 Main St')
);
await verifierRequest(0n, verifyAddressFailTest);

async function verifierRequest(
  //   key: VendorData,
  index: bigint,
  credentialData: Record
) {
  //   let record = Records.get(key)!;
  let w = Tree.getWitness(index);
  let witness = new MyMerkleWitness(w);

  console.log('Verifier request in process...');
  try {
    let tx = await Mina.transaction(feePayer, () => {
      VendorCredentialZkApp.verifyCredential(credentialData, witness);
    });
    await tx.prove();
    await tx.sign([feePayerKey, zkappKey]).send();

    console.log('Credentials verified!');
  } catch (ex: any) {
    console.log(
      'Vendor credential does not match. Credentials are not verified'
    );
  }
}

console.log('Shutting down');

await shutdown();
