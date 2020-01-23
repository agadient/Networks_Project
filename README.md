# Setup

You need 3 Ubuntu 16.04 VMs. 

Install bitcoin using apt install

Install the nfqueue from following the instructions of this github: https://github.com/TrustRouter/nfqueue-bindings

DO NOT use the pip install Netfilterqueue library, it does not work. (I say this from personal experience)

Install other dependencies for the python script using pip

The VMS will be Alice, Bob, and Cindy Their ips should be 172.16.132.164 , 172.16.132.166, and 172.16.132.165

Ensure that Alice has the Alice_rsa.key (named "rsa.key") and Alice_trusted.keys (named "trusted.keys") files in her ~/.bitcoin directory. Also ensure she has the configuration for node_A in this directory (named "bitcoin.conf")

Do this for Bob and Cindy. Bob and Cindy both use the node_B configuration file

Run sudo encrypt.py for Bob and Cindy, it doesn't matter which order.

Do the same on Alice only after Bob and Cindy have their scripts running. 

You should have the bitcoin protocol running between Alice and Cindy, authenticated by Bob!

Also note that the pcapng files are just examples of what you should be seeing with and without encryption
