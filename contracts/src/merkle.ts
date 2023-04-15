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
} from 'snarkyjs';

await isReady;

const doProofs = true;

class MyMerkleWitness extends MerkleWitness(8) {}

class Account extends CircuitValue {
  @prop publicKey: PublicKey;
  @prop points: UInt32;

  constructor(publicKey: PublicKey, points: UInt32) {
    super(publicKey, points);
    this.publicKey = publicKey;
    this.points = points;
  }

  hash(): Field {
    return Poseidon.hash(this.toFields());
  }

  addPoints(n: number): Account {
    return new Account(this.publicKey, this.points.add(n));
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
  verifyCredential(
    credentialStatus: Field,
    account: Account,
    path: MyMerkleWitness
  ) {
    // this is our hash! its the hash of the preimage "22", but keep it a secret!
    let target = Field(
      '17057234437185175411792943285768571642343179330449434169483610110583519635705'
    );

    // if our credentialStatus preimage hashes to our target, credential is verified!
    Poseidon.hash([credentialStatus]).assertEquals(target);

    // // we fetch the on-chain commitment
    // let commitment = this.commitment.get();
    // this.commitment.assertEquals(commitment);

    // // we check that the account is within the committed Merkle Tree
    // path.calculateRoot(account.hash()).assertEquals(commitment);

    // // we update the account and grant one point!
    // let newAccount = account.addPoints(1);

    // // we calculate the new Merkle Root, based on the account changes
    // let newCommitment = path.calculateRoot(newAccount.hash());

    // this.commitment.set(newCommitment);
  }
}

type Names = 'Bob' | 'Alice' | 'Charlie' | 'Olivia';

let Local = Mina.LocalBlockchain({ proofsEnabled: doProofs });
Mina.setActiveInstance(Local);
let initialBalance = 10_000_000_000;

let feePayerKey = Local.testAccounts[0].privateKey;
let feePayer = Local.testAccounts[0].publicKey;

// the zkapp account
let zkappKey = PrivateKey.random();
let zkappAddress = zkappKey.toPublicKey();

// this map serves as our off-chain in-memory storage
let Accounts: Map<string, Account> = new Map<Names, Account>();

let bob = new Account(Local.testAccounts[0].publicKey, UInt32.from(0));
let alice = new Account(Local.testAccounts[1].publicKey, UInt32.from(0));
let charlie = new Account(Local.testAccounts[2].publicKey, UInt32.from(0));
let olivia = new Account(Local.testAccounts[3].publicKey, UInt32.from(0));

Accounts.set('Bob', bob);
Accounts.set('Alice', alice);
Accounts.set('Charlie', charlie);
Accounts.set('Olivia', olivia);

// we now need "wrap" the Merkle tree around our off-chain storage
// we initialize a new Merkle Tree with height 8
const Tree = new MerkleTree(8);

Tree.setLeaf(0n, bob.hash());
Tree.setLeaf(1n, alice.hash());
Tree.setLeaf(2n, charlie.hash());
Tree.setLeaf(3n, olivia.hash());

// now that we got our accounts set up, we need the commitment to deploy our contract!
initialCommitment = Tree.getRoot();

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

// console.log('Initial points: ' + Accounts.get('Bob')?.points);

console.log('Verifier checking a credential..');
await verifierRequest('Bob', 0n, 21);

// console.log('Final points: ' + Accounts.get('Bob')?.points);

async function verifierRequest(
  name: Names,
  index: bigint,
  credentialStatus: number
) {
  let account = Accounts.get(name)!;
  let w = Tree.getWitness(index);
  let witness = new MyMerkleWitness(w);

  console.log('Verifier request in process...');
  try {
    let tx = await Mina.transaction(feePayer, () => {
      VendorCredentialZkApp.verifyCredential(
        Field(credentialStatus),
        account,
        witness
      );
    });
    await tx.prove();
    await tx.sign([feePayerKey, zkappKey]).send();

    console.log('Credentials verified!');
  } catch (ex: any) {
    console.log('Vendor credential not verified: ');
    console.log('*********************PRIVATE MESSAGE*********************');
    console.log(ex.message);
    console.log('*********************************************************');
  }

  //   // if the transaction was successful, we can update our off-chain storage as well
  //   account.points = account.points.add(1);
  //   Tree.setLeaf(index, account.hash());
  //   VendorCredentialZkApp.commitment.get().assertEquals(Tree.getRoot());
}

console.log('Shutting down');

await shutdown();
