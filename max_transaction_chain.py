import requests
def max_chain(wallet_id,max_arr=[]):
    max_arr.append(wallet_id)
    data=requests.get('https://blockchain.info/rawaddr/'+wallet_id)
    if(data.status_code==429):
        return([max_arr])
    d=data.json()
    if 'error' in d:
        print("Error: Could not access data related to given wallet.")
        return([max_arr])
    wallet=d['address']
    if d['total_sent']==0:
        return([max_arr])
    max_amt_sent=0
    sent_to=[]
    for i in d['txs']:
        tr_amt=0
        for j in i["out"]:
            if j["addr"]==wallet:
                tr_amt+=j["value"]
        if tr_amt>max_amt_sent:
            for j in i["inputs"]:
                if j["prev_out"]["addr"] not in sent_to:
                    sent_to.append(j["prev_out"]["addr"])
    temp_max=[]
    for i in sent_to:
        ind_arr=max_arr[:]
        temp_max+=max_chain(i,ind_arr)
    return(temp_max)

print(max_chain('bc1qp6k6tux6g3gr3sxw94g9tx4l0cjtu2pt65r6xp'))