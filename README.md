# Crypto.com Council Node on local machine

![Chain v.: 0.5](https://img.shields.io/badge/Chain%20v.-0.5-green) ![Environment: Local  (Intel)](https://img.shields.io/badge/Environment-Local%20(Intel)-blue) ![OS: Ubuntu 18.04](https://img.shields.io/badge/OS-Ununtu%2018.04-orange) ![Complexety: Intermediate](https://img.shields.io/badge/Complexety-Intermediate-yellow)

This is the documentation on how to create a council node for Crypto.com chain on its version 0.5 on a physical machine running Ubuntu 18.04
You basically need a local machine with some specific characteristics and some specific software running on it

## Local machine
You need a computer with a processor compatible with SGX instructions. The cheapest one I've found in Spain is this:

* Computer: https://www.pccomponentes.com/barebone-intel-nuc-nuc7cjyh2-intel-celeron-j4005
* Memory: https://www.pccomponentes.com/goodram-sodimm-ddr4-2400mhz-8gb-cl17
* Hard Drive: https://www.pccomponentes.com/kingston-a400-ssd-120-gb

> For a total of 182€ (at the 5th of August 2020) you can have it all.

If you want to check out if your current computer can process SGX instructions (or you're looking for advice when getting a new computer) check this repo: https://github.com/ayeks/SGX-hardware

> :warning: **Important!**
> If you choose the Intel NUC like I did, you will need to change something on the BIOS in order to activate SGX and disable the SecureBoot. Take note of these images:

Click here to select "Security"
![Select Security](https://github.com/diereysaa/cryptocom_council_node_on_local/blob/master/bios_01.jpg)

This has to be “Enabled”
![Set Enabled](https://github.com/diereysaa/cryptocom_council_node_on_local/blob/master/bios_02.jpg)

Deactivate this:
![Deactivate SecureBoot](https://github.com/diereysaa/cryptocom_council_node_on_local/blob/master/bios_03.jpg)

## Operating system
You need to install Ubuntu 18.04 Server. I won't explain how to install Ubuntu on a fresh machine, but you can follow this guide if you need to: https://www.fosslinux.com/6406/how-to-install-ubuntu-server-18-04-lts.htm

## Software install
You need to connect by SSH/Telnet to the machine, if you need help with that, please follow this guide: https://www.digitalocean.com/community/tutorials/how-to-use-ssh-to-connect-to-a-remote-server-in-ubuntu  

#### Initial updates:
```shell
sudo apt update && sudo apt upgrade -y && sudo apt autoremove
sudo apt install -y gcc dkms jq unzip
```

#### Check if you have SGX support:
```shell
wget https://raw.githubusercontent.com/ayeks/SGX-hardware/master/test-sgx.c
gcc test-sgx.c -o test-sgx
./test-sgx
```

#### It has to show something like this:
```shell
ubuntu@intel-nuc:~$ ./test-sgx
eax: 706a1 ebx: 400800 ecx: 4ff8ebbf edx: bfebfbff
stepping 1
model 10
family 6
processor type 0
extended model 7
extended family 0
smx: 0

Extended feature bits (EAX=07H, ECX=0H)
eax: 0 ebx: 2294e287 ecx: 40400004 edx: ac000400
sgx available: 1
sgx launch control: 1

CPUID Leaf 12H, Sub-Leaf 0 of Intel SGX Capabilities (EAX=12H,ECX=0)
eax: 3 ebx: 1 ecx: 0 edx: 241f
sgx 1 supported: 1
sgx 2 supported: 1
MaxEnclaveSize_Not64: 1f
MaxEnclaveSize_64: 24
```
The important parts are these:
```shell
sgx available: 1
sgx 1 supported: 1
```

#### I strongly recommend to work inside a subfolder within your home directory, so you need to create it and get in:
```shell
cd ~
mkdir crypto_node
cd crypto_node
```

> :warning: This whole guide will assume you're using the `~/crypto_node` folder. If you're using a different one, take care with all the upcoming commands


#### Install the SGX SDK
```shell
sudo apt-get install -y libssl-dev libcurl4-openssl-dev libprotobuf-dev
sudo apt-get install -y build-essential python
```

#### You need to download the most updated version of the driver and the SDK. Check this page, and download the most updated versions:
https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/

*(As of 5th of August 2020 these are the most updated files)*
```shell
wget https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.33.bin
wget https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.9.101.2.bin
wget https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.6.0_95eaa6f.bin
```

#### Install the drivers
```shell
sudo chmod +x sgx_linux_x64_driver_1.33.bin 
sudo ./sgx_linux_x64_driver_1.33.bin
sudo chmod +x sgx_linux_x64_driver_2.6.0_95eaa6f.bin 
sudo ./sgx_linux_x64_driver_2.6.0_95eaa6f.bin
```

#### After all this, you need to reboot the machine:
```shell
sudo reboot now
```

#### Always, after rebooting, remember to come back to the working folder:
```shell
cd ~/crypto_node
```

#### In order to check everything went fine, let's see if the device is ready:
```shell
ubuntu@intel-nuc:~$ ls -l /dev/isgx
crw-rw-rw- 1 root root 10, 54 Aug  9 09:31 /dev/isgx
```

#### Install the SGX PSW:
```shell
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y libsgx-launch libsgx-urts
sudo apt-get install -y libsgx-epid libsgx-urts
sudo apt-get install -y libsgx-quote-ex libsgx-urts
```

#### Install the SGX SDK:
```shell
chmod +x sgx_linux_x64_sdk_2.9.101.2.bin 
sudo ./sgx_linux_x64_sdk_2.9.101.2.bin 
## We need to confirm with "Yes" when asked
source /home/ubuntu/crypto_node/sgxsdk/environment
```

#### Since you're using Ubuntu 18.04, it's recommended to add the mitigation tool
```shell
wget https://download.01.org/intel-sgx/sgx-linux/2.9/as.ld.objdump.gold.r1.tar.gz
sudo tar -xf as.ld.objdump.gold.r1.tar.gz
cd external/toolset/
sudo chmod +x *
sudo cp * /usr/local/bin
cd ../..
```

#### Install AESMD as a service
```shell
sudo apt install -y libsgx-uae-service
sudo apt install -y libzmq3-dev
```

#### Install tendermint
```shell
sudo apt update
curl -LOJ https://github.com/tendermint/tendermint/releases/download/v0.33.7/tendermint_v0.33.7_linux_amd64.zip
unzip tendermint_v0.33.7_linux_amd64.zip
```

#### Install Crypto.com chain
```shell
curl -LOJ https://github.com/crypto-com/chain/releases/download/v0.5.3/crypto-com-chain-release-0.5.3.tar.gz
tar -zxvf crypto-com-chain-release-0.5.3.tar.gz
```

#### Configure tendermint
```shell
./tendermint init
cd ~/crypto_node/.tendermint/config/
curl https://raw.githubusercontent.com/crypto-com/chain-docs/master/docs/getting-started/assets/genesis_file/v0.5/genesis.json > ~/crypto_node/.tendermint/config/genesis.json
```

#### Let's check tendermint was installed correctly:
```shell
[ $(md5sum genesis.json | awk '{print $1}') = "1c518490f523153f5a644d47deb1a3c1" ] && echo "OK!" || echo "MISMATCHED"
## Should be showing "OK!"
```

#### Check AESMC is running
```shell
ps ax | grep aesm
```
It should show something like this:
```shell
23159 ?        Ssl    0:00 /opt/intel/sgx-aesm-service/aesm/aesm_service
24540 pts/0    S+     0:00 grep --color=auto aesm
```

At this point you have all the software ready and installed. Now it's time to...

### Create the Council Node

#### Add environment variables
```shell
nano ~/.bash_profile
```
You have to paste the following:
```shell
export CRYPTO_CHAIN_ID=testnet-thaler-crypto-com-chain-42
export CRYPTO_CLIENT_TENDERMINT=ws://13.90.34.32:26657/websocket
```
Save, exit, and then:
```shell
source ~/.bash_profile
```

#### You need to create the wallet *(change "<WALLET_NAME>" for your desired name)*
```shell
cd ~/crypto_node
./client-cli wallet new --name <WALLET_NAME> --type hd
```

#### It will ask for your passphrase (twice) and then it will show your Recovery Seed and the Authentication Token:
```shell
Please store following mnemonic safely to restore your wallet later: 
Mnemonic: word word word word word word word word word word word word 
Authentication token: 28***************************************************de
```

>:warning: Write down the authentication token, because you will be using it a lot from now on. 
> And the recovery seed as well, of course.

#### Create the staking address
```shell
./client-cli address new --name <WALLET_NAME> --type Staking
## Add the Authentification token and it will return the new Staking address
New address: 0x9121b59be9********************53fe22
```
Again, take note of the address for later use

Now you need to send a message to the gitter chat community (https://gitter.im/crypto-com/community), so either @devashishdxt or @lezzokafka can topup our staking address with some test CROs. 
This is the message I sent, but you can elaborate your own:
>Hi y'all, @devashishdxt @lezzokafka I've just finished installing the thaler node, and created my staking address: 0x912*******************************22
>I would love to receive some test CROs to keep on working. TiA!

*You can change the text if you want, but basically it's about tagging these two users, and pasting your staking address*

#### Once they confirmed they've topped up our address, you need to sync your wallet:
```shell
./client-cli sync --name <WALLET_NAME>
```
*(This will take quite long (around 6 hours now that we're on block 320k, but you can shut it down and restart, and it will pick up where it left)*

#### Once the sync finish, you can check the Test CRO have arrived:
```shell
./client-cli state --name <WALLET_NAME> --address 0x9121b59be9********************53fe22
```
It should show something like this:
```shell
+-------------------+----------------------------+
| Nonce             |                          0 |
+-------------------+----------------------------+
| Bonded            |          60000000.00000000 |
+-------------------+----------------------------+
| Unbonded          |                 0.00000000 |
+-------------------+----------------------------+
| Unbonded From     | 1970-01-01 00:00:00 +00:00 |
+-------------------+----------------------------+
| Jailed Until      |                 Not jailed |
+-------------------+----------------------------+
| Last Slash Type   |                Not slashed |
+-------------------+----------------------------+
| Last Slash Amount |                Not slashed |
+-------------------+----------------------------+
| Last Slash Time   |                Not slashed |
+-------------------+----------------------------+
```

#### With the wallet sync'd and the tCROs ready, you need to setup `tendermint`
```shell
./tendermint init
sed -i '/seeds = /c\seeds = "f3806de90c43f5474c6de2b5edefb81b9011f51f@52.186.66.214:26656,29fab3b66ee6d9a46a4ad0cc1b061fbf02024354@13.71.189.105:26656,2ab2acc873250dccc3eb5f6eb5bd003fe5e0caa7@51.145.98.33:26656"' ~/crypto_node/.tendermint/config/config.toml
sed -i '/create_empty_blocks_interval = /c\create_empty_blocks_interval = "60s"' ~/crypto_node/.tendermint/config/config.toml
sed -i '/index_all_tags = /c\index_all_tags = true' ~/crypto_node/.tendermint/config/config.toml
```

#### Let's check the `tendermint` config is available
```shell
ls -l  ~/crypto_node/.tendermint/config/priv_validator_key.json 
-rw------- 1 ubuntu ubuntu 345 Aug  4 17:39 /home/ubuntu/crypto_node/.tendermint/config/priv_validator_key.json
```

#### Now you need a value from the `priv_validator_key.json`
```shell
cat /home/ubuntu/.tendermint/config/priv_validator_key.json
```

#### It will return something like this:
```shell
{
  "address": "3B2F*******************20FB",
  "pub_key": {
    "type": "tendermint/PubKeyEd25519",
    "value": "oiuy****************************Z31QU="
  },
  "priv_key": {
    "type": "tendermint/PrivKeyEd25519",
    "value": "Pz**********************************************Q=="
  }
}
```
The important value here is the `pub_key` (oiuy****************************Z31QU= in this case)

#### Sometimes, `chain-abci` is not available on the working folder, so let's copy it over:
```shell
cp chain-abci-HW-debug/chain-abci ./chain-abci
cp chain-abci-HW-debug/tx_validation_enclave.signed.so ./tx_validation_enclave.signed.so
```

### Launching everything as a service

#### Now you need to create the listeners for the services that will run in the background, and will resist a reboot of your machine
```shell
sudo nano /etc/systemd/system/chain-listener.service
```

#### Then paste this:
```shell
[Unit]
Description=Crypto.com chain-abci listener
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=ubuntu
LimitNOFILE=65536
Environment="RUST_LOG=info"
WorkingDirectory=/home/ubuntu/crypto_node
ExecStart=/home/ubuntu/crypto_node/chain-abci --chain_id testnet-thaler-crypto-com-chain-42 --genesis_app_hash F62DDB49D7EB8ED0883C735A0FB7DE7F2A3FA322FCD2AA832F452A62B38607D5 --enclave_server ipc:///home/ubuntu/crypto_node/enclave.socket

[Install]
WantedBy=multi-user.target
```

And then, execute:
```shell
sudo systemctl enable chain-listener.service
sudo systemctl start chain-listener.service
```

#### Now, reboot the machine:
```shell
sudo reboot now
```

#### After rebooting, the `chain-listener` should be working in the background and you can check it by running:
```shell
sudo journalctl -u chain-listener.service -f
```
*(Exit with Ctrl+C)*

#### Then you need to make the same for `tendermint`
```shell
sudo nano /etc/systemd/system/node-listener.service
```

#### Paste this:
```shell
[Unit]
Description=Crypto.com tendermint node listener
After=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=1
User=ubuntu
LimitNOFILE=65536
WorkingDirectory=/home/ubuntu/crypto_node
ExecStart=/home/ubuntu/crypto_node/tendermint node --home /home/ubuntu/crypto_node/.tendermint

[Install]
WantedBy=multi-user.target
```

#### And then, execute:
```shell
sudo systemctl enable node-listener.service
sudo systemctl start node-listener.service
```

#### And again, you need to reboot the machine:
```shell
sudo reboot now
```

#### After rebooting, the `node-listener` should be working in the background and you can check it by running:
```shell
sudo journalctl -u node-listener.service -f
```

> :warning: The `tendermint node` command will retrieve the whole blockchain, so depending on the current state of the network, it could take some time.
> Example: as of 5th of August 2020, we are on block ~320.000, so `tendermint node` will take ~24 hours to catch up.

#### With this command you can check what's the current block height, to know how far `tendermint node` is:
```shell
curl -s http://13.90.34.32:26657/commit | jq "{height: .result.signed_header.header.height}"
```

#### Just before joining the node council it's **REALLY IMPORTANT** that your wallet to be sync'd with the blockchain, so execute this again:
```shell
./client-cli sync --name <WALLET_NAME>
```

#### As soon as the wallet is sync'd you can sent the `node-join` request: 
```shell
./client-cli transaction new --name <WALLET_NAME> --type node-join
```

It will ask you several things:

* Authentication token
* Staking address
* Validator node name (Be creative! :smile: )
* Validator pub-key (the one from the `priv_validator_key.json` file)

And at the end, it will show a **wonderful** message:
```shell
Transaction successfully created!
```

**YAY! :grin: :clap: :grin:**

#### If you want to check if the node is signing correctly, you can execute this:
```shell
wget https://raw.githubusercontent.com/crypto-com/chain-docs/master/docs/getting-started/assets/signature_checking/check-validator-up.sh
chmod +x check-validator-up.sh 
./check-validator-up.sh --tendermint-url http://13.90.34.32:26657 --pubkey "<YOUR_VALIDATOR_PUBLICKEY>"
```

And it will reply something like this:
```shell
The validator is in the council nodes set under the address A0DD*****************************111
The validator is signing @ Block#338405 👍
```

---

# Thanks!
I would like to say thankyou to all the people on the gitter channel, and specifically to @calvinlauco, @lezzokafka for the general support and @alive29 for the services idea/script.
