import requests
def single_intr(wallet_id):
    data=requests.get('https://blockchain.info/rawaddr/'+wallet_id)
    d=data.json()
    if 'error' in d:
        print("Error: Could not access data related to given wallet.")
        return([])
    wallet=d['address']
    interacted_with_wallets=[]
    interacted_with_wallets_d={}
    single_interaction=[]
    for i in d['txs']:
        for j in i['inputs']:
            if j['prev_out']['addr'] not in interacted_with_wallets and j['prev_out']['addr']!=wallet:
                interacted_with_wallets.append(j['prev_out']['addr'])
                interacted_with_wallets_d[j['prev_out']['addr']]=[1,0]
            elif j['prev_out']['addr']!=wallet:
                interacted_with_wallets_d[j['prev_out']['addr']][0]+=1
        for j in i['out']:
            if j['addr'] not in interacted_with_wallets and j['addr']!=wallet:
                interacted_with_wallets.append(j['addr'])
                interacted_with_wallets_d[j['addr']]=[0,1]
            elif j['addr']!=wallet:
                interacted_with_wallets_d[j['addr']][1]+=1
    for i in interacted_with_wallets_d:
        if interacted_with_wallets_d[i]==[0,1] or interacted_with_wallets_d[i]==[1,0] or interacted_with_wallets_d[i]==[1,1]:
            single_interaction.append(i)
    return(single_interaction)

print(single_intr('bc1qmvlq0ec8sltfgc5m70aa2knsc3wv2l2kne3k8p'))