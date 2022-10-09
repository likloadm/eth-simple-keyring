const {
  stripHexPrefix,
  bufferToHex,
  toBuffer,
  ecrecover,
  pubToAddress,
  isValidAddress,
} = require('likloadm-ethereumjs-util');
const { keccak256 } = require('ethereum-cryptography/keccak');
const {
  encrypt,
  getEncryptionPublicKey,
  personalSign,
  recoverPersonalSignature,
  recoverTypedSignature,
  signTypedData,
  SignTypedDataVersion,
} = require('@metamask/eth-sig-util');
const {
  TransactionFactory,
  Transaction: EthereumTx,
} = require('@ethereumjs/tx');
const SimpleKeyring = require('..');

const TYPE_STR = 'Simple Key Pair';

// Sample account:
const testAccount = {
  key: '0x5851b0151e02f731ee9dd4c747062884ac70b048b99c1ee74b057c0ffb0dfd00cc16cac6e897e1c21658d642fdb107e3ccf8d5079d30cb95acfba766c4af9a7c6dd06c7fefca189592552a35d862ef1f412ffd860193e6c7092c23aca2d13aa483d2d707fc631925fa6d2944600e31afd642a9d399741f66bf6e8a2be7758a2c73317752b6e0044016c849a3d4ce34e70ac722b39360755c0ddea9a8222f8e3a65ab24bab0194635873a83ef384cd12912370b3ce5f6b0a155c992afd3d039ea74c856a67f24a1ab060244395f07985654345f2701b7a831136a31d9480acb076002026cd81b02437806551696f097b5bf0b0ff7b487bba0278fffa7a04f7a1451783ca7259e35df11786c2ec5a19ede0453733fc5ce08c42d7de5cec5b4e3945f4d4a59d873b823cbc510c777c01426b5568405f3f17d50fd0d45f9a1e985465966c3ba6986d3b9994f41b3dc9b7cc6e938533c056fe94d0b532015aa189d892f1faf749b0e46594da99e9f96a1883a6ab7c1dd33273ec50d868d64df97507281143845ea48d77d1b773ab00234d38ca1ed89f5df20bdd73390c36e982b4cca55c0f18649db3fb600552a2cb1a62091cbf49d0b778895aa4d6e78627c16c12b399f3f88f484009598b6c3e11a504101022494d7348049cfe146f71ef4e6445fcf3f18a1a17bac22e30f25caa6bc22eed8d7baa515d1fa430da9cf2a9c6ef7d106beffa7a7edea8377aee9d89caa92f17aa380bd0128813d15d0eb84b3f6c773c951e809952e7a28d1336cd863f10a39d40c42d15fe75d9f6b8db5c4e1ac2fcc97daaa3a9440d517510de1486f3b510cccc3595ad18b9cdf5a6a4b0f17dbeb82d3a8bb04843a1bea7db57a9570ed89c526735b2abe49e6a7d2ca5b67ee9b7a96498cc49c593ed4448fec36443911fffe139c2973df07f69701bd00044c18c7f0811da4bb92962f1bf5076ec2689a927921494f0eaeb9c358161591613821b3ab819493dd79d1cfa5a0b399341424b1e1994b90dc9dad741f2d9cf37f5a26a46afbe71f027ebb591e6134bed3bcaef22a42135568b911bd5618e704e3c77c6b32b2be3fcb16bea770eb76b80c95bf29b648ea49ba9f723839acecdd7093bdfe5bc5e11f28d1d1b381ab24f676360a707b3bd6cfbeea48dce5bd0d171123e3225d04af0a01d180cb53ca62c3b2efa4e4c84797265f3a8cecbaa7d1236fa7795c618143113c9625ca9d12a8ca444ff84c3f058b936cbedae9cd525e4dbdb55552a4379a0e5da1d6e3920b29156d0bb90d760f3b711c938e2f9bfd8cd12d2515f72bc75d63882b924662ef044969a4e7015a55017a74a76812fc6c8c14a0bbdf4fcc53603e5f94d1c637e4047f85d0d6aa34a45e77966bd648fbb21b033af4420f47e28343c4e7d73fb8628a7b3c43d6e2c7d3801fb4bce79b89148eeaec54e88aa38c85f630ba2795712e84af84d31cc84971d5575703a307a2d92d2564515cb0da7b013aa1a914e6fa33b7e9ad64aac2538fd23808f0258bbc2b9c1504a58f0155cca15afd558c8fffbd08bb0fe89fcc662e2d0e73ed6ee2a100ce96befeca19248295d82f14a60eb2580c2f7077c7733ff8b5c379591afd87c2672a651502bdcf706c019fbc1d5707dd17839326b25ea06a6b687a6decf7f8160bb1150587a7ffbec16aff21b69a80573ca3dd94ecd9979c3a0f34848417c1a81636751d3d3ceba4016c5676b000dfc720babcd3e66b3cc4205b609955679db7ead6053c375ea007cffe2eb3086ca412b4c5759cffd188e1a5524894674db89bc7c46a22f7846fcd90f621e8a58018a9f1acbbae182b88c864c3126eae06291bafd3b68637e1a9c73bd3ed2c60845a631719cf871bf109c5e46f7c3b20a4d94092884f39e89d68e1072d3a0939529660f94827e58f65aa19283502c403ffd5cfdb081278d1eeec823f3a2ca2133c5dc7915d900371800445144d16957bbfca7d7a545cc51e39ded1b771fb9f47e55e2332ddd0b2f146c9ab90cb93213e8d9bad67fe8de54e8d7b885e49484775234553176f7573fa9062dee36e9ad5ccbc91d5ac6de2ba80d219600ed7fd7aecfe5e3cafdcf2dd852773493d41b07c105a79b9f9fc567d02653d611a678ec786348ada2c53c3e67a5c6d503ff9af7d1dd6d8537ddc5091bc9644e1e0e93be036687a332686ce097278411c21840b119e5e8822e69069d6db64da6e8a3ac5e7b65a52888482aa6b7ca4894beae53313d2fc01f5b55c75af5fcad0c7ccb8eb2eae33d3ec38c3ee9e8c135c47afe54cea83a8fb2a7f10a9e6cdfe85ec728796980d10fdf0326a2351b3bd7fbd71f924f7d7e97bad6c4a3aeb4db130c98a956800453f1cfc28a4a4c0e13d0b5397fe926b9f5bf3d538789fffb5b123e58b3f65302f78c2a6fb0b11796120a845295ffe61a49208f631d38921b7a549e7184af7cf2bdae7341e1224734d748ad145af54d268caebadbc9cd8bb13dd2e2e11685abee3e45fff52526879b515035555001010dea57dd1d98406acd6b57d3afc549a5bf701af964f40910cb737af64f36d534105955b42dc360374793f10af718accbc2842810c68aa72e6d0900b8386b8bb47f675c40fc3eb2f1ae75a3716653692885ed8df08b231243e1b71ba726e02b9d7ab519a0ec2d5ad22338f34edce5df1b8b76709a067e002a953c28018baeb2e2d7fc788993b01474ba053a5c06cf2eba847473c462b977f833a4921eb6bee97afa72708f5a30044209a0643',
  address: '0x98b6de1927e916bfc1618097b35c06b0d113fce2',
};

const notKeyringAddress = '0xbD20F6F5F1616947a39E11926E78ec94817B3931';

describe('simple-keyring', function () {
  let keyring;
  beforeEach(function () {
    keyring = new SimpleKeyring();
  });

  describe('Keyring.type', function () {
    it('is a class property that returns the type string.', function () {
      const { type } = SimpleKeyring;
      expect(type).toBe(TYPE_STR);
    });
  });

  describe('#serialize empty wallets.', function () {
    it('serializes an empty array', async function () {
      const output = await keyring.serialize();
      expect(output).toHaveLength(0);
    });
  });

  describe('#deserialize a private key', function () {
    it('serializes what it deserializes', async function () {
      await keyring.deserialize([testAccount.key]);
      const serialized = await keyring.serialize();
      expect(serialized).toHaveLength(1);
      expect(serialized[0]).toBe(stripHexPrefix(testAccount.key));
    });
  });

  describe('#constructor with a private key', function () {
    it('has the correct addresses', async function () {
      const newKeyring = new SimpleKeyring([testAccount.key]);
      const accounts = await newKeyring.getAccounts();
      expect(accounts).toStrictEqual([testAccount.address]);
    });
  });

  describe('#signTransaction', function () {
    const address = '0x98b6de1927e916bfc1618097b35c06b0d113fce2';
    const privateKey =
      '0x5851b0151e02f731ee9dd4c747062884ac70b048b99c1ee74b057c0ffb0dfd00cc16cac6e897e1c21658d642fdb107e3ccf8d5079d30cb95acfba766c4af9a7c6dd06c7fefca189592552a35d862ef1f412ffd860193e6c7092c23aca2d13aa483d2d707fc631925fa6d2944600e31afd642a9d399741f66bf6e8a2be7758a2c73317752b6e0044016c849a3d4ce34e70ac722b39360755c0ddea9a8222f8e3a65ab24bab0194635873a83ef384cd12912370b3ce5f6b0a155c992afd3d039ea74c856a67f24a1ab060244395f07985654345f2701b7a831136a31d9480acb076002026cd81b02437806551696f097b5bf0b0ff7b487bba0278fffa7a04f7a1451783ca7259e35df11786c2ec5a19ede0453733fc5ce08c42d7de5cec5b4e3945f4d4a59d873b823cbc510c777c01426b5568405f3f17d50fd0d45f9a1e985465966c3ba6986d3b9994f41b3dc9b7cc6e938533c056fe94d0b532015aa189d892f1faf749b0e46594da99e9f96a1883a6ab7c1dd33273ec50d868d64df97507281143845ea48d77d1b773ab00234d38ca1ed89f5df20bdd73390c36e982b4cca55c0f18649db3fb600552a2cb1a62091cbf49d0b778895aa4d6e78627c16c12b399f3f88f484009598b6c3e11a504101022494d7348049cfe146f71ef4e6445fcf3f18a1a17bac22e30f25caa6bc22eed8d7baa515d1fa430da9cf2a9c6ef7d106beffa7a7edea8377aee9d89caa92f17aa380bd0128813d15d0eb84b3f6c773c951e809952e7a28d1336cd863f10a39d40c42d15fe75d9f6b8db5c4e1ac2fcc97daaa3a9440d517510de1486f3b510cccc3595ad18b9cdf5a6a4b0f17dbeb82d3a8bb04843a1bea7db57a9570ed89c526735b2abe49e6a7d2ca5b67ee9b7a96498cc49c593ed4448fec36443911fffe139c2973df07f69701bd00044c18c7f0811da4bb92962f1bf5076ec2689a927921494f0eaeb9c358161591613821b3ab819493dd79d1cfa5a0b399341424b1e1994b90dc9dad741f2d9cf37f5a26a46afbe71f027ebb591e6134bed3bcaef22a42135568b911bd5618e704e3c77c6b32b2be3fcb16bea770eb76b80c95bf29b648ea49ba9f723839acecdd7093bdfe5bc5e11f28d1d1b381ab24f676360a707b3bd6cfbeea48dce5bd0d171123e3225d04af0a01d180cb53ca62c3b2efa4e4c84797265f3a8cecbaa7d1236fa7795c618143113c9625ca9d12a8ca444ff84c3f058b936cbedae9cd525e4dbdb55552a4379a0e5da1d6e3920b29156d0bb90d760f3b711c938e2f9bfd8cd12d2515f72bc75d63882b924662ef044969a4e7015a55017a74a76812fc6c8c14a0bbdf4fcc53603e5f94d1c637e4047f85d0d6aa34a45e77966bd648fbb21b033af4420f47e28343c4e7d73fb8628a7b3c43d6e2c7d3801fb4bce79b89148eeaec54e88aa38c85f630ba2795712e84af84d31cc84971d5575703a307a2d92d2564515cb0da7b013aa1a914e6fa33b7e9ad64aac2538fd23808f0258bbc2b9c1504a58f0155cca15afd558c8fffbd08bb0fe89fcc662e2d0e73ed6ee2a100ce96befeca19248295d82f14a60eb2580c2f7077c7733ff8b5c379591afd87c2672a651502bdcf706c019fbc1d5707dd17839326b25ea06a6b687a6decf7f8160bb1150587a7ffbec16aff21b69a80573ca3dd94ecd9979c3a0f34848417c1a81636751d3d3ceba4016c5676b000dfc720babcd3e66b3cc4205b609955679db7ead6053c375ea007cffe2eb3086ca412b4c5759cffd188e1a5524894674db89bc7c46a22f7846fcd90f621e8a58018a9f1acbbae182b88c864c3126eae06291bafd3b68637e1a9c73bd3ed2c60845a631719cf871bf109c5e46f7c3b20a4d94092884f39e89d68e1072d3a0939529660f94827e58f65aa19283502c403ffd5cfdb081278d1eeec823f3a2ca2133c5dc7915d900371800445144d16957bbfca7d7a545cc51e39ded1b771fb9f47e55e2332ddd0b2f146c9ab90cb93213e8d9bad67fe8de54e8d7b885e49484775234553176f7573fa9062dee36e9ad5ccbc91d5ac6de2ba80d219600ed7fd7aecfe5e3cafdcf2dd852773493d41b07c105a79b9f9fc567d02653d611a678ec786348ada2c53c3e67a5c6d503ff9af7d1dd6d8537ddc5091bc9644e1e0e93be036687a332686ce097278411c21840b119e5e8822e69069d6db64da6e8a3ac5e7b65a52888482aa6b7ca4894beae53313d2fc01f5b55c75af5fcad0c7ccb8eb2eae33d3ec38c3ee9e8c135c47afe54cea83a8fb2a7f10a9e6cdfe85ec728796980d10fdf0326a2351b3bd7fbd71f924f7d7e97bad6c4a3aeb4db130c98a956800453f1cfc28a4a4c0e13d0b5397fe926b9f5bf3d538789fffb5b123e58b3f65302f78c2a6fb0b11796120a845295ffe61a49208f631d38921b7a549e7184af7cf2bdae7341e1224734d748ad145af54d268caebadbc9cd8bb13dd2e2e11685abee3e45fff52526879b515035555001010dea57dd1d98406acd6b57d3afc549a5bf701af964f40910cb737af64f36d534105955b42dc360374793f10af718accbc2842810c68aa72e6d0900b8386b8bb47f675c40fc3eb2f1ae75a3716653692885ed8df08b231243e1b71ba726e02b9d7ab519a0ec2d5ad22338f34edce5df1b8b76709a067e002a953c28018baeb2e2d7fc788993b01474ba053a5c06cf2eba847473c462b977f833a4921eb6bee97afa72708f5a30044209a0643';
    const txParams = {
      from: address,
      nonce: '0x00',
      gasPrice: '0x09184e72a000',
      gasLimit: '0x2710',
      to: address,
      value: '0x1000',
    };

    it('returns a signed legacy tx object', async function () {
      await keyring.deserialize([privateKey]);
      const tx = new EthereumTx(txParams);
      expect(tx.isSigned()).toBe(false);

      const signed = await keyring.signTransaction(address, tx);
      expect(signed.isSigned()).toBe(true);
    });

    it('returns a signed tx object', async function () {
      await keyring.deserialize([privateKey]);
      const tx = TransactionFactory.fromTxData(txParams);
      expect(tx.isSigned()).toBe(false);

      const signed = await keyring.signTransaction(address, tx);
      expect(signed.isSigned()).toBe(true);
    });

    it('returns rejected promise if empty address is passed', async function () {
      await keyring.deserialize([privateKey]);
      const tx = TransactionFactory.fromTxData(txParams);
      await expect(keyring.signTransaction('', tx)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if wrong address is passed', async function () {
      await keyring.deserialize([privateKey]);
      const tx = TransactionFactory.fromTxData(txParams);
      await expect(
        keyring.signTransaction(notKeyringAddress, tx),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#signMessage', function () {
    const address = '0x9858e7d8b79fc3e6d989636721584498926da38a';
    const message =
      '0x879a053d4800c6354e76c7985a865d2922c82fb5b3f4577b2fe08b998954f2e0';
    const privateKey =
      '0x7dd98753d7b4394095de7d176c58128e2ed6ee600abe97c9f6d9fd65015d9b18';
    const expectedResult =
      '0x28fcb6768e5110144a55b2e6ce9d1ea5a58103033632d272d2b5cf506906f7941a00b539383fd872109633d8c71c404e13dba87bc84166ee31b0e36061a69e161c';

    it('passes the dennis test', async function () {
      await keyring.deserialize([privateKey]);
      const result = await keyring.signMessage(address, message);
      expect(result).toBe(expectedResult);
    });

    it('reliably can decode messages it signs', async function () {
      await keyring.deserialize([privateKey]);
      const localMessage = 'hello there!';
      const msgHashHex = bufferToHex(keccak256(Buffer.from(localMessage)));

      await keyring.addAccounts(9);
      const addresses = await keyring.getAccounts();
      const signatures = await Promise.all(
        addresses.map(async (accountAddress) => {
          return await keyring.signMessage(accountAddress, msgHashHex);
        }),
      );
      signatures.forEach((sgn, index) => {
        const accountAddress = addresses[index];

        const r = toBuffer(sgn.slice(0, 66));
        const s = toBuffer(`0x${sgn.slice(66, 130)}`);
        const v = BigInt(`0x${sgn.slice(130, 132)}`);
        const m = toBuffer(msgHashHex);
        const pub = ecrecover(m, v, r, s);
        const adr = `0x${pubToAddress(pub).toString('hex')}`;

        expect(adr).toBe(accountAddress);
      });
    });

    it('throw error for invalid message', async function () {
      await keyring.deserialize([privateKey]);
      await expect(keyring.signMessage(address, '')).rejects.toThrow(
        'Cannot convert 0x to a BigInt',
      );
    });

    it('throw error if empty address is passed', async function () {
      await keyring.deserialize([privateKey]);
      await expect(keyring.signMessage('', message)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if address not associated with the current keyring is passed', async function () {
      await keyring.deserialize([privateKey]);
      await expect(
        keyring.signMessage(notKeyringAddress, message),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#addAccounts', function () {
    describe('with no arguments', function () {
      it('creates a single wallet', async function () {
        await keyring.addAccounts();
        const serializedKeyring = await keyring.serialize();
        expect(serializedKeyring).toHaveLength(1);
      });
    });

    describe('with a numeric argument', function () {
      it('creates that number of wallets', async function () {
        await keyring.addAccounts(3);
        const serializedKeyring = await keyring.serialize();
        expect(serializedKeyring).toHaveLength(3);
      });
    });
  });

  describe('#getAccounts', function () {
    it('should return a list of addresses in wallet', async function () {
      // Push a mock wallet
      keyring.deserialize([testAccount.key]);

      const output = await keyring.getAccounts();
      expect(output).toHaveLength(1);
      expect(output[0]).toBe(testAccount.address);
    });
  });

  describe('#removeAccount', function () {
    describe('if the account exists', function () {
      it('should remove that account', async function () {
        await keyring.addAccounts();
        const addresses = await keyring.getAccounts();
        expect(addresses).toHaveLength(1);
        keyring.removeAccount(addresses[0]);
        const addressesAfterRemoval = await keyring.getAccounts();
        expect(addressesAfterRemoval).toHaveLength(0);
      });
    });

    describe('if the account does not exist', function () {
      it('should throw an error', function () {
        const unexistingAccount = '0x0000000000000000000000000000000000000000';
        expect(() => keyring.removeAccount(unexistingAccount)).toThrow(
          `Address ${unexistingAccount} not found in this keyring`,
        );
      });
    });
  });

  describe('#signPersonalMessage', function () {
    const address = '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb';
    const privateKey = Buffer.from(
      '6969696969696969696969696969696969696969696969696969696969696969',
      'hex',
    );
    const privKeyHex = bufferToHex(privateKey);
    const message = '0x68656c6c6f20776f726c64';
    const expectedSignature =
      '0xce909e8ea6851bc36c007a0072d0524b07a3ff8d4e623aca4c71ca8e57250c4d0a3fc38fa8fbaaa81ead4b9f6bd03356b6f8bf18bccad167d78891636e1d69561b';

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signPersonalMessage(address, message);
      expect(signature).toBe(expectedSignature);

      const restored = recoverPersonalSignature({
        data: message,
        signature,
      });
      expect(restored).toBe(address);
    });

    it('throw error if empty address is passed', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(keyring.signPersonalMessage('', message)).rejects.toThrow(
        'Must specify address.',
      );
    });

    it('throw error if wrong address is passed', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(
        keyring.signPersonalMessage(notKeyringAddress, message),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#signTypedData', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';
    const expectedSignature =
      '0x49e75d475d767de7fcc67f521e0d86590723d872e6111e51c393e8c1e2f21d032dfaf5833af158915f035db6af4f37bf2d5d29781cd81f28a44c5cb4b9d241531b';

    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!',
      },
    ];

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData);
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });

    it('returns the expected value if invalid version is given', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'FOO',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V1', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';
    const expectedSignature =
      '0x49e75d475d767de7fcc67f521e0d86590723d872e6111e51c393e8c1e2f21d032dfaf5833af158915f035db6af4f37bf2d5d29781cd81f28a44c5cb4b9d241531b';

    const typedData = [
      {
        type: 'string',
        name: 'message',
        value: 'Hi, Alice!',
      },
    ];

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V1',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });

    it('works via version paramter', async function () {
      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData);
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V1,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V3', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '0x4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V3',
      });
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V3 signature verification', function () {
    const privKeyHex =
      'c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4';
    const expectedSignature =
      '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
          ],
          Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' },
          ],
          Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person' },
            { name: 'contents', type: 'string' },
          ],
        },
        primaryType: 'Mail',
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        message: {
          from: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
          },
          to: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
          },
          contents: 'Hello, Bob!',
        },
      };

      await keyring.deserialize([privKeyHex]);
      const addresses = await keyring.getAccounts();
      const [address] = addresses;
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V3',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V3,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#signTypedData V4', function () {
    const address = '0x29c76e6ad8f28bb1004902578fb108c507be341b';
    const privKeyHex =
      '0x4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      await keyring.deserialize([privKeyHex]);
      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V4',
      });
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V4,
      });
      expect(restored).toBe(address);
    });
  });

  describe('#decryptMessage', function () {
    const address = '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb';
    const privateKey = Buffer.from(
      '6969696969696969696969696969696969696969696969696969696969696969',
      'hex',
    );
    const privKeyHex = bufferToHex(privateKey);
    const message = 'Hello world!';
    const encryptedMessage = encrypt({
      publicKey: getEncryptionPublicKey(privateKey),
      data: message,
      version: 'x25519-xsalsa20-poly1305',
    });

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const decryptedMessage = await keyring.decryptMessage(
        address,
        encryptedMessage,
      );
      expect(message).toBe(decryptedMessage);
    });

    it('throw error if address passed is not present in the keyring', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(
        keyring.decryptMessage(notKeyringAddress, encryptedMessage),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });

    it('throw error if wrong encrypted data object is passed', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(keyring.decryptMessage(address, {})).rejects.toThrow(
        'Encryption type/version not supported.',
      );
    });
  });

  describe('#encryptionPublicKey', function () {
    const address = '0xbe93f9bacbcffc8ee6663f2647917ed7a20a57bb';
    const privateKey = Buffer.from(
      '6969696969696969696969696969696969696969696969696969696969696969',
      'hex',
    );
    const publicKey = 'GxuMqoE2oHsZzcQtv/WMNB3gCH2P6uzynuwO1P0MM1U=';
    const privKeyHex = bufferToHex(privateKey);

    it('returns the expected value', async function () {
      await keyring.deserialize([privKeyHex]);
      const encryptionPublicKey = await keyring.getEncryptionPublicKey(
        address,
        privateKey,
      );
      expect(publicKey).toBe(encryptionPublicKey);
    });

    it('throw error if address is blank', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(
        keyring.getEncryptionPublicKey('', privateKey),
      ).rejects.toThrow('Must specify address.');
    });

    it('throw error if address is not present in the keyring', async function () {
      await keyring.deserialize([privKeyHex]);
      await expect(
        keyring.getEncryptionPublicKey(notKeyringAddress, privateKey),
      ).rejects.toThrow('Simple Keyring - Unable to find matching address.');
    });
  });

  describe('#signTypedData V4 signature verification', function () {
    const privKeyHex =
      'c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4';
    const expectedSignature =
      '0x65cbd956f2fae28a601bebc9b906cea0191744bd4c4247bcd27cd08f8eb6b71c78efdf7a31dc9abee78f492292721f362d296cf86b4538e07b51303b67f749061b';

    it('returns the expected value', async function () {
      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
          ],
          Person: [
            { name: 'name', type: 'string' },
            { name: 'wallets', type: 'address[]' },
          ],
          Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person[]' },
            { name: 'contents', type: 'string' },
          ],
          Group: [
            { name: 'name', type: 'string' },
            { name: 'members', type: 'Person[]' },
          ],
        },
        domain: {
          name: 'Ether Mail',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        primaryType: 'Mail',
        message: {
          from: {
            name: 'Cow',
            wallets: [
              '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
              '0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
            ],
          },
          to: [
            {
              name: 'Bob',
              wallets: [
                '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
                '0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57',
                '0xB0B0b0b0b0b0B000000000000000000000000000',
              ],
            },
          ],
          contents: 'Hello, Bob!',
        },
      };

      await keyring.deserialize([privKeyHex]);

      const addresses = await keyring.getAccounts();
      const [address] = addresses;

      const signature = await keyring.signTypedData(address, typedData, {
        version: 'V4',
      });
      expect(signature).toBe(expectedSignature);
      const restored = recoverTypedSignature({
        data: typedData,
        signature,
        version: SignTypedDataVersion.V4,
      });
      expect(restored).toBe(address);
    });
  });

  describe('getAppKeyAddress', function () {
    it('should return a public address custom to the provided app key origin', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);

      const appKeyAddress = await simpleKeyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(address).not.toBe(appKeyAddress);
      expect(isValidAddress(appKeyAddress)).toBe(true);
    });

    it('should return different addresses when provided different app key origins', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);

      const appKeyAddress1 = await simpleKeyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await simpleKeyring.getAppKeyAddress(
        address,
        'anotherapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress2)).toBe(true);
      expect(appKeyAddress1).not.toBe(appKeyAddress2);
    });

    it('should return the same address when called multiple times with the same params', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);

      const appKeyAddress1 = await simpleKeyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress1)).toBe(true);

      const appKeyAddress2 = await simpleKeyring.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      expect(isValidAddress(appKeyAddress2)).toBe(true);
      expect(appKeyAddress1).toBe(appKeyAddress2);
    });

    it('should throw error if the provided origin is not a string', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);

      await expect(simpleKeyring.getAppKeyAddress(address, [])).rejects.toThrow(
        `'origin' must be a non-empty string`,
      );
    });

    it('should throw error if the provided origin is an empty string', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);

      await expect(simpleKeyring.getAppKeyAddress(address, '')).rejects.toThrow(
        `'origin' must be a non-empty string`,
      );
    });
  });

  describe('exportAccount', function () {
    it('should return a hex-encoded private key', async function () {
      const { address } = testAccount;
      const simpleKeyring = new SimpleKeyring([testAccount.key]);
      const privKeyHexValue = await simpleKeyring.exportAccount(address);
      expect(testAccount.key).toBe(`0x${privKeyHexValue}`);
    });

    it('throw error if account is not present', async function () {
      await expect(keyring.exportAccount(notKeyringAddress)).rejects.toThrow(
        'Simple Keyring - Unable to find matching address.',
      );
    });
  });

  describe('signing methods withAppKeyOrigin option', function () {
    it('should signPersonalMessage with the expected key when passed a withAppKeyOrigin', async function () {
      const { address } = testAccount;
      const message = '0x68656c6c6f20776f726c64';

      const privateKeyHex =
        '4fbe006f0e9c2374f53eb1aef1b6970d20206c61ea05ad9591ef42176eb842c0';
      const privateKey = Buffer.from(privateKeyHex, 'hex');
      const expectedSignature = personalSign({ privateKey, data: message });

      const simpleKeyring = new SimpleKeyring([testAccount.key]);
      const signature = await simpleKeyring.signPersonalMessage(
        address,
        message,
        {
          withAppKeyOrigin: 'someapp.origin.io',
        },
      );

      expect(expectedSignature).toBe(signature);
    });

    it('should signTypedData V3 with the expected key when passed a withAppKeyOrigin', async function () {
      const { address } = testAccount;
      const typedData = {
        types: {
          EIP712Domain: [],
        },
        domain: {},
        primaryType: 'EIP712Domain',
        message: {},
      };

      const privateKeyHex =
        '4fbe006f0e9c2374f53eb1aef1b6970d20206c61ea05ad9591ef42176eb842c0';
      const privateKey = Buffer.from(privateKeyHex, 'hex');
      const expectedSignature = signTypedData({
        privateKey,
        data: typedData,
        version: SignTypedDataVersion.V3,
      });

      const simpleKeyring = new SimpleKeyring([testAccount.key]);
      const signature = await simpleKeyring.signTypedData(address, typedData, {
        withAppKeyOrigin: 'someapp.origin.io',
        version: 'V3',
      });

      expect(expectedSignature).toBe(signature);
    });
  });
});
