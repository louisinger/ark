# vHTLC 

## Description

vHTLC are identified by the following taproot descriptor:

```
tr(unspendable, {
  {
      {
          and(and(pk(sender), pk(receiver)), pk(asp)), // REFUND
          and(older(reclaim_timeout), and(pk(sender), pk(asp))) // RECLAIM with asp
      },
      {
          and(older(reclaim_alone_timeout), pk(sender)), // RECLAIM without asp
          and(older(refund), and(pk(receiver), pk(asp))) // REFUND without sender
      }
  },
  {
      and(hash160(preimage_hash), and(pk(receiver), pk(asp))), // CLAIM (forfeit)
      and(hash160(preimage_hash), and(older(exit_timeout), pk(receiver))) // CLAIM (unilateral exit)
  }
})
```

_current implementation does not support RECLAIM and REFUND cases_

## Test it with CLI

### Send to vHTLC

```bash
ark send --amount 5000 --preimage 01020304 --to tark1q2rnq7dqpywfk94t68uv2zpjpvrlp4gpgngfente9n5uj9w6cczx2q48h6gz5hsh906p3gj8zqff7r698072u3jd57q2ntgtxu20q6ys0vqdnpyg 
```

_this command will send to a vHTLC locked by the pubkey of the receiver address, the secret preimage is `01020304`. Note that we don't need the preimage itself but only the hash of the preimage. for testing purpose, hash is done by the CLI._

### Claim from vHTLC

> `ark vtxos` is a new utility command on this branch aiming to list all the vtxos owned by the wallet. Use it to get the outpoint of the vHTLC output you want to claim.

```bash
ark claim  --preimage 01020304 --outpoints "67d9b301de647a621e21fb456f5d305de745219b8c50f8b76a16a67b03548bc4:0"
```

_this command will claim the vHTLC output "67d9b301de647a621e21fb456f5d305de745219b8c50f8b76a16a67b03548bc4:0" with the preimage `01020304`._

To claim (or spend) a vHTLC, the wallet must sign the input with its secret key AND add the preimage as unknown psbt field. The server will check the preimage hash along with the signature to validate the claim.
