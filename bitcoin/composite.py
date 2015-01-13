# Takes privkey, address, value (satoshis), fee (satoshis)
def send(frm,to,value,fee=1000):
    u = unspent(privtoaddr(frm))
    u2 = select(u,value+fee)
    tx = mksend(to+':'+str(value),privtoaddr(to),fee)
    tx2 = signall(tx,privtoaddr(to))
    pushtx(tx)


def get_multisig_pubkeys(script_hex):
    if not script_hex:
        return 0, []
    script = deserialize_script(script_hex)
    if len(script) < 4:
        return 0, []
    if type(script[0]) != int or type(script[-2]) != int:
        return 0, []
    if script[0] < 1 or script[0] > 20:
        return 0, []
    if script[-2] != len(script) - 3:
        return 0, []
    if script[-1] != 0xae:
        return 0, []
    pubkeys = script[1:-2]
    for p in pubkeys:
        try:
            decode_pubkey(p)
        except:
            return 0, []
    return script[0], pubkeys


def smart_multisign(tx, *private_keys):
    
    # assumes obj tx, assume hex or wif private_keys 
    
    public_keys = [privtopub(p) for p in private_keys]
    tx_bin = serialize(tx).decode('hex')
    for i, txin in enumerate(tx['ins']):
        multisig_m, multisig_keys = 0, []
        sigs = []
        txin['complete'] = False
        
        # if no script_pubkey try to guess it from script
        if not txin.get('script_pubkey'):
            if txin.get('script'):
                script = deserialize_script(txin['script'])
                # p2sh multisig 
                if script[0] is None:
                    multisig_m, multisig_keys = get_multisig_pubkeys(script[-1])
                    if multisig_m and multisig_keys:
                        sigs = filter(bool, script[1:-1])
                        txin['script_pubkey'] = script[-1]
                # looks like a p2pkh
                elif len(script) == 2 and isinstance(script[0], str) and isinstance(script[1], str):
                    sig, public_key = script
                    txin['script_pubkey'] = mk_pubkey_script(pubtoaddr(public_key))
            # if no script_pubkey nor script but a single private_key assume p2pkh script_pubkey
            if len(public_keys) == 1 and multisig_m == 0:
                txin['script_pubkey'] = mk_pubkey_script(pubtoaddr(public_keys[0]))
        # we actually have a script_pubkey
        else:
            if txin.get('script'):
                script = deserialize_script(txin['script'])
                if script[0] is None:
                    sigs = filter(bool, script[1:-1])
                    # make sure script_pubkey matches p2sh script
                    if script[-1] != txin['script_pubkey']:
                        txin['complete'] = False
                        continue
            multisig_m, multisig_keys = get_multisig_pubkeys(txin['script_pubkey'])
        
        # we don't know how to sign this input, skip it
        if not txin.get('script_pubkey'):
            continue
        
        script_pubkey_bin = txin['script_pubkey'].decode('hex')
        modtx = signature_form(tx_bin, i, script_pubkey_bin)
        
        # sign multisig
        if multisig_m and multisig_keys:
            pubkey_sig_map = {}
            for sig in sigs:
                for multisig_key in multisig_keys:
                    hashcode = decode(sig[-2:],16)
                    if ecdsa_tx_verify(modtx, sig, multisig_key, hashcode):
                        pubkey_sig_map[multisig_key] = sig
                        break
            # if we need more sigs try to get more
            if len(pubkey_sig_map) < multisig_m:
                for j, public_key in enumerate(public_keys):
                    if public_key in multisig_keys and public_key not in pubkey_sig_map:
                        pubkey_sig_map[public_key] = ecdsa_tx_sign(modtx, private_keys[j])
            # combine the sigs
            combined_sigs = [pubkey_sig_map[p] for p in multisig_keys if p in pubkey_sig_map]
            combined_sigs = combined_sigs[:multisig_m]
            script = [None] + combined_sigs + [txin['script_pubkey']]
            txin['script'] = serialize_script(script)
            txin['complete'] = len(combined_sigs) == multisig_m
        # sign p2pkh
        else:
            if txin.get('script'):
                script = deserialize_script(txin['script'])
                if len(script) == 2 and isinstance(script[0], str) and isinstance(script[1], str):
                    sig, public_key = script
                    if txin['script_pubkey'] == mk_pubkey_script(pubtoaddr(public_key)):
                        hashcode = decode(sig[-2:],16)
                        txin['complete'] = ecdsa_tx_verify(modtx, sig, public_key, hashcode)
            for j, public_key in enumerate(public_keys):
                if mk_pubkey_script(pubtoaddr(public_key)) == txin['script_pubkey']:
                    sig = ecdsa_tx_sign(modtx, private_keys[j])
                    txin['script'] = serialize_script([sig, public_key])
                    txin['complete'] = True
                    break
    
    tx['complete'] = bool([i for i in tx['ins'] if i['complete']])
    
    return serialize(tx)