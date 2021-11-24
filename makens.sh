#!/bin/bash
cd vnetUtils/examples
bash ./makeVNet < $1
cd ../helper
bash ./execNS $2 bash