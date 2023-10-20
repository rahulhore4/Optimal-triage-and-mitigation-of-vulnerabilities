from gurobipy import Model, quicksum, GRB
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn import preprocessing
from collections import Counter
import copy

df = pd.read_csv("data_final_nessus.csv", index_col = 0)


    
crit_host = []
for r in zip(df['Host'],df['Criticality of Servers-Score'],df['Susceptibility of Hosts-Score'],df['High-Value Asset Identification-Score']):

    if r[1] >=0.75 and r[2]>=0.75 and r[3] >= 0.75:
        crit_host.append(r[0])


crit_machines = []
for t,j in Counter(crit_host).items():
    print(t)
    print(j)
    crit_machines.append(t)

crit_machines_dict = {}
for idx,name in enumerate(df['Host'].value_counts().index.tolist()):
    if name in crit_machines:
        crit_machines_dict[name] = df['Host'].value_counts()[idx]
    # print('Name :', name)
    # print('Counts :', df['Host'].value_counts()[idx])

len(crit_host)    


# m1 = '131.247.181.99'
# m2 = '131.247.186.101'
# m3 = '131.247.181.40'
# m4 = '131.247.181.41'
# m5 = '131.247.181.42'
# m6 = '131.247.181.43'
# m7 = '131.247.181.58'
# m8 = '131.247.181.99'
# m9 = '131.247.182.148'
# m10 = '131.247.182.149'
# m11 = '131.247.182.33'
# m12 = '131.247.182.34'
# m13 = '131.247.182.4'
# m14 = '131.247.182.56'
# m15 = '131.247.186.100'
# m16 = '131.247.186.118'
# m17 = '131.247.186.119'
# m18 = '131.247.186.120'
# m19 = '131.247.186.48'
# m20 = '131.247.186.66'

# m1_count = 0


# for r in zip(df['Host']):
#     if r[0] == m1: #'131.247.220.32'
#         m1_count +=1

    

# m2_count = 0
# for r in zip(df['Host']):
#     if r[0] == m2:
#         m2_count +=1

jk = df[df['Criticality of Servers-Score']==1]['Host']
total_webdataservers_no = len(jk)

jk1 = df[df['Susceptibility of Hosts-Score']==1]['Host']
total_lowprotectionmachine_no = len(jk1)

jk2 = df[df['High-Value Asset Identification-Score']==1]['Host']
total_highvalueasset_no = len(jk2)

length = len(df)
T = 10000
df['Allocation with Composite Score'] = 0
df['Allocation with Criticality'] = 0
df['Allocation with Susceptibility'] = 0
df['Allocation with High value assets'] = 0
df['Allocation with CVSS'] = 0
df['Allocation with Max no'] = 0
df['Allocation with VULCON'] = 0


t1_time = df[df['Type'] == 1]['Personnel-Hour']
t2_time = df[df['Type'] == 2]['Personnel-Hour']
t3_time = df[df['Type'] == 3]['Personnel-Hour']
t4_time = df[df['Type'] == 4]['Personnel-Hour']
t5_time = df[df['Type'] == 5]['Personnel-Hour']
t6_time = df[df['Type'] == 6]['Personnel-Hour']

p1_time = sum(t1_time) + sum(t3_time)
p2_time = sum(t2_time) + sum(t4_time)
p3_time = sum(t5_time) + 5000
p4_time = sum(t6_time) + 4540

time_typ = [sum(t1_time)/60,sum(t2_time)/60,sum(t3_time)/60,sum(t4_time)/60,sum(t5_time)/60,sum(t6_time)/60,5000/60,4550/60]
#fig = plt.figure()
#ax = fig.add_axes([0,0,1,1])
langs = ['Type 1', 'Type 2', 'Type 3', 'Type 4', 'Type 5', 'Type 6','Type 7', 'Type 8']
ptypes = ['Type 1', 'Type 2', 'Type 3', 'Type 4']
students = [p1_time,p2_time,p3_time,p4_time]
occur = [796, 125, 4292, 1764, 805, 248, 55, 50 ]
#time_typ = [sum(t1_time),sum(t2_time),sum(t3_time),sum(t4_time),sum(t5_time),sum(t6_time)]
plt.bar(langs,time_typ)
plt.xlabel('Type of Vulnerabilities')
plt.ylabel('Estimated Mitigation Time (in hours)')
#plt.savefig('Fig 7.pdf', dpi=300, bbox_inches='tight')



num = 52

def getScore(tempDF, colName):
    mitigatedRisk = tempDF[ tempDF[colName] != 0 ]['Composite Score']
    return sum(mitigatedRisk)

def getTime(tempDF, colName):
    res = []
    pickedInstance = tempDF[tempDF[colName] != 0]
    res = pickedInstance['Personnel-Hour']
    return sum(res)
    
def gotPicked(tempDF, s, colName, v):
    pickedInstance = tempDF[tempDF[s] != 0]
    ret = pickedInstance[pickedInstance[colName] == v]
    #print(s, v)
    return len(ret)


def gotPickedRange(tempDF, s, colName, v1, v2):
    pickedInstance = tempDF[tempDF[s] != 0]
    pickedInstance = pickedInstance[pickedInstance[colName]*10 <= v2]
    pickedInstance = pickedInstance[pickedInstance[colName]*10 >= v1]
    return len(pickedInstance)

#ALlocation with Composite Score
########################################
df_composite = df[['CVE', 'Host', 'Criticality of Servers-Score', 'Susceptibility of Hosts-Score',
       'High-Value Asset Identification-Score', 'CVSS Normalized-Score',
       'Personnel-Hour', 'Composite Score', 'Allocation with Composite Score','Specialist']].copy()
df_composite['newIndex'] = df_composite.index.values.tolist()
df_composite['Type'] = df['Type']
df_allocation  = pd.DataFrame()

allocation1_count_list = []
allocation2_count_list = []
allocation3_count_list = []
allocation4_count_list = []
mit_counter_dict1 = {}
for m in crit_machines:
    mit_counter_dict1[m] = []
df_allocation = pd.DataFrame()

for indx1 in range(num):
    temp_hour = []
    temp_type = []
    time_type1 = []
    time_type2 = []
    time_type3 = []
    time_type4 = []
    allocations1 = []
    allocations2= []
    allocations3= []
    allocations4= []
    original_index = []
    df_allocation_temp = pd.DataFrame()
    U = df['Personnel-Hour']
    u = U.to_numpy()

    A = df['Composite Score']
    a = A.to_numpy()

    F = df['Allocation with Composite Score']
    f = F.to_numpy()
    
    E = df['CVSS Normalized-Score']
    e = E.to_numpy()

    ## Model with composite Score
    model = Model('IT PROJECT')

    x = model.addVars(length, vtype= GRB.BINARY)

    model.addConstr((quicksum((u[i] * x[i] )for i in range(length))<= T
                     ))

    for i in range(length):

        model.addConstr(f[i] + x[i] <= 1)
        
        #model.addConstr(e[i] - x[i] >= -0.8)
        
        #model.addConstr(a[i] - x[i] >= -0.8)

    model.setObjective((quicksum((x[i]*a[i]) for i in range(length))),GRB.MAXIMIZE)
    
    result = model.optimize()
    # print(df_composite)

    x_values = [int(x[i].x) for i in range(length)]
    type(x_values)
    df['Allocation with Composite Score'] = df['Allocation with Composite Score'] + x_values
    
    df_composite['Allocation with Composite Score'] =  df['Allocation with Composite Score']
    
    string = 'Allocation with Composite Score- Iter'+ str(indx1+1)
    df_composite[string] = x_values
    
    
    temp_machine = {}
    for y in crit_machines:
        temp_machine[y] = 0
    for r in zip(df_composite[string],df_composite['Host']):
        if r[0] ==1:
            if r[1] in crit_machines:
                temp_machine[r[1]] += 1

    host_copy = copy.deepcopy(crit_machines)
    for keys,items in temp_machine.items():
        host_copy.remove(keys)
        mit_counter_dict1[keys].append(items)
    if len(host_copy)!=0:
        for el in host_copy:
             mit_counter_dict1[el].append(0)
        
        
        

    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
    
    temp_hour = df_composite[df_composite[string] == 1]['Personnel-Hour']
    temp_hour.index = list(range(len(temp_hour)))
    print(len(temp_hour))
    temp_type = df_composite[df_composite[string] == 1]['Specialist']
    original_index = temp_type.index.values.tolist()
    temp_type.index = list(range(len(temp_hour)))
    
    for i in range(len(temp_hour)):
        if temp_type[i] == 1:
            t1 = temp_hour[i]
            time_type1.append(t1)
        elif temp_type[i] == 2:
            t2 = temp_hour[i]* 1.2
            time_type1.append(t2)
        elif temp_type[i] == 3:
            t3 = temp_hour[i]* 1.1
            time_type1.append(t3)
        else:
            t4 = temp_hour[i]* 1.2
            time_type1.append(t4)
            
    for i in range(len(temp_hour)):
        if temp_type[i] == 2:
            t1 = temp_hour[i]
            time_type2.append(t1)
        elif temp_type[i] == 1:
            t2 = temp_hour[i]* 1.2
            time_type2.append(t2)
        elif temp_type[i] == 3:
            t3 = temp_hour[i]* 1.2
            time_type2.append(t3)
        else:
            t4 = temp_hour[i]* 1.1
            time_type2.append(t4)


    for i in range(len(temp_hour)):
        if temp_type[i] == 3:
            t1 = temp_hour[i]
            time_type3.append(t1)
        elif temp_type[i] == 1:
            t2 = temp_hour[i]* 1.1
            time_type3.append(t2)
        elif temp_type[i] == 2:
            t3 = temp_hour[i]* 1.2
            time_type3.append(t3)
        else:
            t4 = temp_hour[i]* 1.2
            time_type3.append(t4)

    for i in range(len(temp_hour)):
        if temp_type[i] == 4:
            t1 = temp_hour[i]
            time_type4.append(t1)
        elif temp_type[i] == 1:
            t2 = temp_hour[i]* 1.2
            time_type4.append(t2)
        elif temp_type[i] == 2:
            t3 = temp_hour[i]* 1.1
            time_type4.append(t3)
        else:
            t4 = temp_hour[i]* 1.2
            time_type4.append(t4)
            
    model = Model('Allocation')

    x = model.addVars([ind for ind in range(len(temp_hour))],[1,2,3,4], vtype= GRB.BINARY)
    
    d = model.addVars(4, vtype= GRB.INTEGER)
    
    m = model.addVar(vtype= GRB.INTEGER)
    for j in range(len(temp_hour)):
        
        model.addConstr(x[j,1] + x[j,2] + x[j,3] + x[j,4] == 1)
        
    model.addConstr(quicksum(x[l,1]*time_type1[l] for l in range(0,len(temp_hour))) <= 6000 + d[0])
    model.addConstr(quicksum(x[l,2]*time_type2[l] for l in range(0,len(temp_hour))) <= 2000 + d[1])
    model.addConstr(quicksum(x[l,3]*time_type3[l] for l in range(0,len(temp_hour))) <= 1500 + d[2])
    model.addConstr(quicksum(x[l,4]*time_type4[l] for l in range(0,len(temp_hour))) <= 500 + d[3])
    model.addConstr(d[0]<= m)
    model.addConstr(d[1]<= m)
    model.addConstr(d[2]<= m)
    model.addConstr(d[3]<= m)
    
    model.setObjective(m,GRB.MINIMIZE)
    
    result = model.optimize()
    
    allocations1 = [int(x[k,1].x) for k in range(len(temp_hour))]
    s1 = sum(allocations1)
    allocation1_count_list.append(s1)
    allocations2 = [int(x[k,2].x) for k in range(len(temp_hour))]
    s2 = sum(allocations2)
    allocation2_count_list.append(s2)
    allocations3 = [int(x[k,3].x) for k in range(len(temp_hour))]
    s3= sum(allocations3)
    allocation3_count_list.append(s3)
    allocations4 = [int(x[k,4].x) for k in range(len(temp_hour))]
    s4 = sum(allocations4)
    allocation4_count_list.append(s4)
    devs = [int(d[indx].x) for indx in range(0,4)]
    
    final_al = allocations1 + allocations2 + allocations3 + allocations4
    df_allocation_temp["Allocations1"] = allocations1
    df_allocation_temp["Allocations2"] = allocations2
    df_allocation_temp["Allocations3"] = allocations3
    df_allocation_temp["Allocations4"] = allocations4
    df_allocation_temp["Original Index"] = original_index

    for i in range(len(df_allocation_temp)):
        if df_allocation_temp.loc[i,'Allocations1'] == 1:
            df_composite.loc[df_allocation_temp.loc[i,'Original Index'],string] = 1
        elif df_allocation_temp.loc[i,'Allocations2'] == 1:
            df_composite.loc[df_allocation_temp.loc[i,'Original Index'],string] = 2
        elif df_allocation_temp.loc[i,'Allocations3'] == 1:
            df_composite.loc[df_allocation_temp.loc[i,'Original Index'],string] = 3
        elif df_allocation_temp.loc[i,'Allocations4'] == 1:
            df_composite.loc[df_allocation_temp.loc[i,'Original Index'],string] = 4

df_composite['Allocation with Type'] = df_composite.loc[:, 'Allocation with Composite Score- Iter1':'Allocation with Composite Score- Iter52'].sum(axis=1)
counter_1 = 0
counter_2 = 0
counter_3 = 0
counter_4 = 0
counter_5 = 0
counter_6 = 0
for indx,rows in df_composite.iterrows():
    if rows['Type'] ==1:
        if rows['Allocation with Type'] == 1:
            counter_1 += 1
    if rows['Type'] ==2:
        if rows['Allocation with Type'] == 2:
            counter_2 += 1
    if rows['Type'] ==3:
        if rows['Allocation with Type'] == 1:
            counter_3 += 1
    if rows['Type'] ==4:
        if rows['Allocation with Type'] == 2:
            counter_4 += 1
    if rows['Type'] ==5:
        if rows['Allocation with Type'] == 3:
            counter_5 += 1
    if rows['Type'] ==6:
        if rows['Allocation with Type'] == 4:
            counter_6 += 1

counter_1s = 0
counter_2s = 0
counter_3s = 0
counter_4s = 0
counter_5s = 0
counter_6s = 0
for indx,rows in df_composite.iterrows():
    if rows['Type'] ==1:
        if rows['Allocation with Type'] != 0:
            counter_1s += 1
    if rows['Type'] ==2:
        if rows['Allocation with Type'] != 0:
            counter_2s += 1
    if rows['Type'] ==3:
        if rows['Allocation with Type'] != 0:
            counter_3s += 1
    if rows['Type'] ==4:
        if rows['Allocation with Type'] != 0:
            counter_4s += 1
    if rows['Type'] ==5:
        if rows['Allocation with Type'] != 0:
            counter_5s += 1
    if rows['Type'] ==6:
        if rows['Allocation with Type'] != 0:
            counter_6s += 1
plotdata = pd.DataFrame({
    "Total Selected":[186, 30, 1156, 170, 265, 21, 15, 16 ],
    "Optimally allocated":[140, 28, 877, 108, 166, 10, 13, 15  ],
    }, 
    index=["Type1", "Type2", "Type3", "Type4", "Type5", "Type6", "Type7", "Type8"]
)
plotdata.plot(kind="bar")
#plt.title("Mince Pie Consumption Study")
plt.xlabel("Type of Vulnerabilities")
plt.ylabel("Number of Vulnerabilities")
plt.savefig('selected and allocated comparison.pdf',orientation='potrait', quality = 30)
    
#Count_list1 = df_allocation_temp["Allocations1"].value_counts()
#Count_list2 = df_composite["Allocated to E-1 at Iter-1"].value_counts()
#Count_list3 = df_composite['Allocation with Composite Score- Iter1'].value_counts()
#Count_list4 = df_composite['Allocation with Composite Score- Iter4'].value_counts()

#df_allocation_temp.iloc[1,1]
df_allocation['Allocated to E-1'] = allocation1_count_list
df_allocation['Allocated to E-2'] = allocation2_count_list
df_allocation['Allocated to E-3'] = allocation3_count_list
df_allocation['Allocated to E-4'] = allocation4_count_list

## Confusion Matrix for the Allocation
rows, cols = (5, 5) 
mat = [[0 for i in range(cols)] for j in range(rows)] 


### row means supposed employee, column means allocated employee
properly_classified = []
total_count = []
properly_classified_percentage = []
e1workhour = []
e2workhour = []
e3workhour = []
e4workhour = []
for it in range(num):
    s = "Allocation with Composite Score- Iter" + str(it+1)
    sum1 = 0
    count = 0
    e1 = 0
    e2 = 0
    e3 = 0
    e4 = 0
    for indx in range(len(df_composite["Host"])):
        y = df_composite[s][indx]
        if y != 0:
            count = count + 1
            x = df_composite["Specialist"][indx]
            x = int(x)
            y = int(y)
            mat[x][y] = mat[x][y] + 1
            workhour = df_composite['Personnel-Hour'][indx]
            if x == y:
                sum1 = sum1 + 1
            else:
                workhour = workhour * 1.1
            if y == 1:
                e1 = e1 + workhour
            elif y == 2:
                e2 = e2 + workhour
            elif y == 3:
                e3 = e3 + workhour
            elif y == 4:
                e4 = e4 + workhour
    e1workhour.append(e1)
    e2workhour.append(e2)
    e3workhour.append(e3)
    e4workhour.append(e4)           
    properly_classified.append(sum1)
    total_count.append(count)
    properly_classified_percentage.append((sum1/count)*100)
          
#Risk Calculation for Allocation with Composite Score
risk_compositeScore = []
requiredTime_compositeScore = []
sum_compositeRiskScore = 0
criticalServers1 = []
tier0_1 = []
tier1_1 = []
tier3_1 = []
tier4_1 = []
lowRiskHosts1 = []
medRiskHosts1 = []
hiRiskHosts1 = []
crtiRiskHosts1 = []
lowSusceptible1 = []
medSusceptible1 = []
hiSusceptible1 = []
percent_criticalServers1 = []
percent_tier0_1  = []
percent_hiSusceptible1 = []

cum_crit_no = 0
cum_tier0_no = 0
cum_highsus_no = 0

for j in range(num):
    strategy = 'Allocation with Composite Score- Iter' + str(j+1)
#strategy = 'Allocation with Composite Score'
    totalMitigatedRisk_compositeScore = getScore(df_composite, strategy)
    risk_compositeScore.append(totalMitigatedRisk_compositeScore)
    sum_compositeRiskScore = sum_compositeRiskScore + totalMitigatedRisk_compositeScore
    
    reqTime = getTime(df_composite, strategy)
    requiredTime_compositeScore.append(reqTime)

    # How many web/database servers
    cat = 'Criticality of Servers-Score'
    val = 1.0 #### how many web/database server
    
    crit_no = gotPicked(df_composite, strategy, cat, val)
    cum_crit_no += crit_no
    criticalServers1.append(crit_no)
    mit_per = cum_crit_no / total_webdataservers_no
    percent_criticalServers1.append(mit_per)
    

    # how many tier 0,1,3,4 
    cat = 'High-Value Asset Identification-Score'
    val = 1.0 #### how many tier0 
    tier0_no = gotPicked(df_composite, strategy, cat, val)
    tier0_1.append( tier0_no )
    cum_tier0_no += tier0_no
    per_tier0 = cum_tier0_no / total_highvalueasset_no
    percent_tier0_1.append(per_tier0)
    
    
    val = 0.75 #### how many tier1
    tier1_1.append( gotPicked(df_composite, strategy, cat, val) )
    val = 0.5 #### how many tier3 
    tier3_1.append( gotPicked(df_composite, strategy, cat, val) )
    val = 0.25 #### how many tier4 
    tier4_1.append( gotPicked(df_composite, strategy, cat, val) )
    
    # how many critical, medium, low
    
    cat = 'CVSS Normalized-Score'
    #### how many low risk hosts
    valLo = 1
    valHi = 3.9
    
    lowRiskHosts1.append( gotPickedRange(df_composite, strategy, cat, valLo, valHi) )

    #### how many medium risk hosts
    valLo = 4
    valHi = 6.9

    medRiskHosts1.append( gotPickedRange(df_composite, strategy, cat, valLo, valHi) )
    
    #### how many high risk hosts
    valLo = 7
    valHi = 8.9
    
    hiRiskHosts1.append( gotPickedRange(df_composite, strategy, cat, valLo, valHi) )
    
    #### how many critical risk hosts
    valLo = 9
    valHi = 10

    crtiRiskHosts1.append( gotPickedRange(df_composite, strategy, cat, valLo, valHi) )
    
    # how many susceptible hosts
    cat = 'Susceptibility of Hosts-Score'
    
    #how many low susceptible
    val = 0.25 
    lowSusceptible1.append( gotPicked(df_composite, strategy, cat, val) )
    #how many medium susceptible
    val = 0.5
    medSusceptible1.append( gotPicked(df_composite, strategy, cat, val) )
    #how many high susceptible
    val = 1.0
    hi_sus_no = gotPicked(df_composite, strategy, cat, val)
    hiSusceptible1.append( hi_sus_no )
    cum_highsus_no += hi_sus_no
    per_hi_sus = cum_highsus_no / total_lowprotectionmachine_no
    
    percent_hiSusceptible1.append(per_hi_sus)

total_tier1 = sum(tier0_1) + sum(tier1_1)
    
################
##Allocation with CVSS
df_CVSS = df[['CVE', 'Host', 'Criticality of Servers-Score', 'Susceptibility of Hosts-Score',
       'High-Value Asset Identification-Score', 'CVSS Normalized-Score',
       'Personnel-Hour', 'Composite Score', 'Allocation with CVSS' ]].copy()


mit_counter_dict5 = {}
for m in crit_machines:
    mit_counter_dict5[m] = []
for indx in range(num):
    
    E = df['CVSS Normalized-Score']
    e = E.to_numpy()

    K = df['Allocation with CVSS']
    k = K.to_numpy()

    ## Model with criticality of servers
    model4 = Model('IT PROJECT4')
    v = model4.addVars(length, vtype= GRB.BINARY)

    model4.addConstr((quicksum((u[i] * v[i] )for i in range(length))<= T))

    for i in range(length):

        model4.addConstr(k[i] + v[i] <= 1)
        
                
        #model4.addConstr(e[i] - v[i] >= -0.6)
        
        #model4.addConstr(a[i] - v[i] >= -0.8)

    model4.setObjective((quicksum((v[i]*e[i]) for i in range(length))),GRB.MAXIMIZE)
    result4 = model4.optimize()
    
    v_values = [int(v[i].x) for i in range(length)]
    
    df['Allocation with CVSS'] = df['Allocation with CVSS'] + v_values
    
    df_CVSS['Allocation with CVSS'] =  df['Allocation with CVSS']
    
 
    string4 = 'Allocation with CVSS- Iter'+ str(indx +1)
    df_CVSS[string4] = v_values
    
    temp_machine = {}
    for y in crit_machines:
        temp_machine[y] = 0
    for r in zip(df_CVSS[string4],df_CVSS['Host']):
        if r[0] ==1:
            if r[1] in crit_machines:
                temp_machine[r[1]] += 1

    host_copy = copy.deepcopy(crit_machines)
    for keys,items in temp_machine.items():
        host_copy.remove(keys)
        mit_counter_dict5[keys].append(items)
    if len(host_copy)!=0:
        for el in host_copy:
             mit_counter_dict5[el].append(0)

    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]


#Risk Calculation for Allocation with CVSS
risk_cvssScore = []
requiredTime_cvssScore = []
sum_cvssRiskScore = 0
criticalServers5 = []
tier0_5 = []
tier1_5 = []
tier3_5 = []
tier4_5 = []
lowRiskHosts5 = []
medRiskHosts5 = []
hiRiskHosts5 = []
crtiRiskHosts5 = []
lowSusceptible5 = []
medSusceptible5 = []
hiSusceptible5 = []

percent_criticalServers5 = []
percent_tier0_5  = []
percent_hiSusceptible5 = []

cum_crit_no = 0
cum_tier0_no = 0
cum_highsus_no = 0

for j in range(num):
    strategy = 'Allocation with CVSS- Iter' + str(j+1)

    totalMitigatedRisk_cvss = getScore(df_CVSS, strategy)
    risk_cvssScore.append(totalMitigatedRisk_cvss)
    sum_cvssRiskScore = sum_cvssRiskScore + totalMitigatedRisk_cvss
    
    reqTime = getTime(df_CVSS, strategy)
    requiredTime_cvssScore.append(reqTime)

    # How many web/database servers
    cat = 'Criticality of Servers-Score'
    val = 1.0 #### how many web/database server
    
    crit_no = gotPicked(df_CVSS, strategy, cat, val)
    criticalServers5.append(crit_no)
    cum_crit_no += crit_no
    per_crit = cum_crit_no/total_webdataservers_no
    percent_criticalServers5.append(per_crit)
    

    # how many tier 0,1,3,4 
    cat = 'High-Value Asset Identification-Score'
    val = 1.0 #### how many tier0 
    
    tier0_no = gotPicked(df_CVSS, strategy, cat, val)
    tier0_5.append( tier0_no )
    cum_tier0_no += tier0_no
    per_tier0 = cum_tier0_no / total_highvalueasset_no
    percent_tier0_5.append(per_tier0)
    val = 0.75 #### how many tier1
    tier1_5.append( gotPicked(df_CVSS, strategy, cat, val) )
    val = 0.5 #### how many tier3 
    tier3_5.append( gotPicked(df_CVSS, strategy, cat, val) )
    val = 0.25 #### how many tier4 
    tier4_5.append( gotPicked(df_CVSS, strategy, cat, val) )
    
    # how many critical, medium, low
    
    cat = 'CVSS Normalized-Score'
    #### how many low risk hosts
    valLo = 1
    valHi = 3.9
    
    lowRiskHosts5.append( gotPickedRange(df_CVSS, strategy, cat, valLo, valHi) )

    #### how many medium risk hosts
    valLo = 4
    valHi = 6.9

    medRiskHosts5.append( gotPickedRange(df_CVSS, strategy, cat, valLo, valHi) )
    
    #### how many high risk hosts
    valLo = 7
    valHi = 8.9
    
    hiRiskHosts5.append( gotPickedRange(df_CVSS, strategy, cat, valLo, valHi) )
    
    #### how many critical risk hosts
    valLo = 9
    valHi = 10

    crtiRiskHosts5.append( gotPickedRange(df_CVSS, strategy, cat, valLo, valHi) )
    
    # how many susceptible hosts
    cat = 'Susceptibility of Hosts-Score'
    
    #how many low susceptible
    val = 0.25 
    lowSusceptible5.append( gotPicked(df_CVSS, strategy, cat, val) )
    #how many medium susceptible
    val = 0.5
    medSusceptible5.append( gotPicked(df_CVSS, strategy, cat, val) )
    #how many high susceptible
    val = 1.0
    hi_sus_no = gotPicked(df_CVSS, strategy, cat, val)
    hiSusceptible5.append( hi_sus_no )
    cum_highsus_no += hi_sus_no
    per_hi_sus = cum_highsus_no / total_lowprotectionmachine_no
    
    percent_hiSusceptible5.append(per_hi_sus)

total_tier5 = sum(tier0_5) + sum(tier1_5)    

################
##Allocation with maximum numver of VIs selected
df_max = df[['CVE', 'Host', 'Criticality of Servers-Score', 'Susceptibility of Hosts-Score',
       'High-Value Asset Identification-Score', 'CVSS Normalized-Score',
       'Personnel-Hour', 'Composite Score', 'Allocation with Max no' ]].copy()

mit_counter_dict6 = {}
for m in crit_machines:
    mit_counter_dict6[m] = []
for indx in range(num):
    L = df['Allocation with Max no']
    l = L.to_numpy()

    ## Model with criticality of servers
    model5 = Model('IT PROJECT5')

    m = model5.addVars(length, vtype= GRB.BINARY)

    model5.addConstr((quicksum((u[i] * m[i] )for i in range(length))<= T))
    for i in range(length):

        model5.addConstr(l[i] + m[i] <= 1)
        
                
        #model5.addConstr(e[i] - m[i] >= -0.6)
        
        #model5.addConstr(a[i] - m[i] >= -0.8)

    model5.setObjective((quicksum((m[i]) for i in range(length))),GRB.MAXIMIZE)


    result5 = model5.optimize()

    m_values = [int(m[i].x) for i in range(length)]


    df['Allocation with Max no'] = df['Allocation with Max no'] + m_values
    
    df_max['Allocation with Max no'] =  df['Allocation with Max no']
    
 
    string4 = 'Allocation with Max no- Iter'+ str(indx +1)
    df_max[string4] = m_values
    
    temp_machine = {}
    for y in crit_machines:
        temp_machine[y] = 0
    for r in zip(df_max[string4],df_max['Host']):
        if r[0] ==1:
            if r[1] in crit_machines:
                temp_machine[r[1]] += 1

    host_copy = copy.deepcopy(crit_machines)
    for keys,items in temp_machine.items():
        host_copy.remove(keys)
        mit_counter_dict6[keys].append(items)
    if len(host_copy)!=0:
        for el in host_copy:
             mit_counter_dict6[el].append(0)

    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]


#Risk Calculation for Allocation with Max No of Vulnerability
risk_maxnoScore = []
requiredTime_maxnoScore = []
sum_maxnoRiskScore = 0
criticalServers6 = []
tier0_6 = []
tier1_6 = []
tier3_6 = []
tier4_6 = []
lowRiskHosts6 = []
medRiskHosts6 = []
hiRiskHosts6 = []
crtiRiskHosts6 = []
lowSusceptible6 = []
medSusceptible6 = []
hiSusceptible6 = []

percent_criticalServers6 = []
percent_tier0_6  = []
percent_hiSusceptible6 = []

cum_crit_no = 0
cum_tier0_no = 0
cum_highsus_no = 0
for j in range(num):
    strategy = 'Allocation with Max no- Iter' + str(j+1)

    totalMitigatedRisk_maxno = getScore(df_max, strategy)
    risk_maxnoScore.append(totalMitigatedRisk_maxno)
    sum_maxnoRiskScore = sum_maxnoRiskScore + totalMitigatedRisk_maxno
    
    reqTime = getTime(df_max, strategy)
    requiredTime_maxnoScore.append(reqTime)

    # How many web/database servers
    cat = 'Criticality of Servers-Score'
    val = 1.0 #### how many web/database server
    
    crit_no = gotPicked(df_max, strategy, cat, val)
    criticalServers6.append(crit_no)
    cum_crit_no += crit_no
    per_crit = cum_crit_no/total_webdataservers_no
    percent_criticalServers6.append(per_crit)

    # how many tier 0,1,3,4 
    cat = 'High-Value Asset Identification-Score'
    val = 1.0 #### how many tier0 
    
    tier0_no = gotPicked(df_max, strategy, cat, val)
    tier0_6.append( tier0_no )
    cum_tier0_no += tier0_no
    per_tier0 = cum_tier0_no / total_highvalueasset_no
    percent_tier0_6.append(per_tier0)
    val = 0.75 #### how many tier1
    tier1_6.append( gotPicked(df_max, strategy, cat, val) )
    val = 0.5 #### how many tier3 
    tier3_6.append( gotPicked(df_max, strategy, cat, val) )
    val = 0.25 #### how many tier4 
    tier4_6.append( gotPicked(df_max, strategy, cat, val) )
    
    # how many critical, medium, low
    
    cat = 'CVSS Normalized-Score'
    #### how many low risk hosts
    valLo = 1
    valHi = 3.9
    
    lowRiskHosts6.append( gotPickedRange(df_max, strategy, cat, valLo, valHi) )

    #### how many medium risk hosts
    valLo = 4
    valHi = 6.9

    medRiskHosts6.append( gotPickedRange(df_max, strategy, cat, valLo, valHi) )
    
    #### how many high risk hosts
    valLo = 7
    valHi = 8.9
    
    hiRiskHosts6.append( gotPickedRange(df_max, strategy, cat, valLo, valHi) )
    
    #### how many critical risk hosts
    valLo = 9
    valHi = 10

    crtiRiskHosts6.append( gotPickedRange(df_max, strategy, cat, valLo, valHi) )
    
    # how many susceptible hosts
    cat = 'Susceptibility of Hosts-Score'
    
    #how many low susceptible
    val = 0.25 
    lowSusceptible6.append( gotPicked(df_max, strategy, cat, val) )
    #how many medium susceptible
    val = 0.5
    medSusceptible6.append( gotPicked(df_max, strategy, cat, val) )
    #how many high susceptible
    val = 1.0
    hi_sus_no = gotPicked(df_max, strategy, cat, val)
    hiSusceptible6.append( hi_sus_no )
    cum_highsus_no += hi_sus_no
    per_hi_sus = cum_highsus_no / total_lowprotectionmachine_no
    
    percent_hiSusceptible6.append(per_hi_sus)   

total_tier6 = sum(tier0_6) + sum(tier1_6)
#ALlocation with VULCON
########################################
df_VULCON = df[['CVE', 'Host', 'Criticality of Servers-Score', 'Susceptibility of Hosts-Score',
       'High-Value Asset Identification-Score', 'CVSS Normalized-Score',
       'Personnel-Hour', 'Composite Score', 'Allocation with Composite Score','Specialist']].copy()
df_VULCON['newIndex'] = df_VULCON.index.values.tolist()
df_VULCON['CVE'] = df['CVE'].fillna('CVE-0-0000')
df_VULCON['Age'] = 0

Age_list = []
for i in range(len(df_VULCON)):
    word = df_VULCON.iloc[i,0]
    w_split = word.split('-')
    Age_list.append(int(w_split[1]))
final_Age_list = [2020-i if i != 0 else 10 for i in Age_list]
 
df_VULCON['Age'] = final_Age_list
x = df_VULCON['Age'].values
x = x.reshape(-1,1) #returns a numpy array
min_max_scaler = preprocessing.MinMaxScaler()
x_scaled = min_max_scaler.fit_transform(x)
df_VULCON['Age'] = x_scaled

#df_VULCON['Persistence'] = 0
#df_VULCON.columns
#df_VULCON['VULCON Score'] = 0.33*df_VULCON['Age'] + 0.33*df_VULCON['Composite Score'] + 0.33*df_VULCON['Persistence']

#new_vulcon = []
#for index, rows in df_VULCON.iterrows():
#     if rows[4] != 1:
#         new_vulcon.append(0.85*rows[13])
#     else:
#        new_vulcon.append(rows[13])
#        
#df_VULCON['VULCON Score'] = new_vulcon
mit_counter_dict7 = {}
for m in crit_machines:
    mit_counter_dict7[m] = []
    
for indx in range(num):
    df_VULCON['Persistence'] = indx / num-1
    df_VULCON['VULCON Score'] = 0.33*df_VULCON['Age'] + 0.33*df_VULCON['Composite Score'] + 0.33*df_VULCON['Persistence']
    new_vulcon = []
    for index, rows in df_VULCON.iterrows():
         if rows[4] != 1:
             new_vulcon.append(0.85*rows[13])
         else:
            new_vulcon.append(rows[13])           
    df_VULCON['VULCON Score'] = new_vulcon
    
    L = df['Allocation with VULCON']
    l = L.to_numpy()
    U = df['Personnel-Hour']
    u = U.to_numpy()
    A = df_VULCON['VULCON Score']
    a= A.to_numpy()

    ## Model with criticality of servers
    model = Model('IT PROJECTVULVON')

    m = model.addVars(length, vtype= GRB.BINARY)

    model.addConstr((quicksum((u[i] * m[i] )for i in range(length))<= T))
    for i in range(length):

        model.addConstr(l[i] + m[i] <= 1)
        
                
        #model5.addConstr(e[i] - m[i] >= -0.6)
        
        #model5.addConstr(a[i] - m[i] >= -0.8)

    model.setObjective((quicksum((m[i]*a[i]) for i in range(length))),GRB.MAXIMIZE)


    result = model.optimize()

    m_values = [int(m[i].x) for i in range(length)]

    df['Allocation with VULCON'] = df['Allocation with VULCON'] + m_values
 
    string4 = 'Allocation with VULCON- Iter'+ str(indx +1)
    df_VULCON[string4] = m_values
    
    temp_machine = {}
    for y in crit_machines:
        temp_machine[y] = 0
    for r in zip(df_VULCON[string4],df_VULCON['Host']):
        if r[0] ==1:
            if r[1] in crit_machines:
                temp_machine[r[1]] += 1

    host_copy = copy.deepcopy(crit_machines)
    for keys,items in temp_machine.items():
        host_copy.remove(keys)
        mit_counter_dict7[keys].append(items)
    if len(host_copy)!=0:
        for el in host_copy:
             mit_counter_dict7[el].append(0)
             
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]


#Risk Calculation for Allocation with VULCON
risk_VULCONScore = []
requiredTime_VULCONScore = []
sum_VULCONRiskScore = 0
criticalServers7 = []
tier0_7 = []
tier1_7 = []
tier3_7 = []
tier4_7 = []
lowRiskHosts7 = []
medRiskHosts7 = []
hiRiskHosts7 = []
crtiRiskHosts7 = []
lowSusceptible7 = []
medSusceptible7 = []
hiSusceptible7 = []

percent_criticalServers7 = []
percent_tier0_7  = []
percent_hiSusceptible7 = []

cum_crit_no = 0
cum_tier0_no = 0
cum_highsus_no = 0

for j in range(num):
    strategy = 'Allocation with VULCON- Iter' + str(j+1)

    totalMitigatedRisk_VULCON = getScore(df_VULCON, strategy)
    risk_VULCONScore.append(totalMitigatedRisk_VULCON)
    sum_VULCONRiskScore = sum_VULCONRiskScore + totalMitigatedRisk_VULCON
    
    reqTime = getTime(df_VULCON, strategy)
    requiredTime_VULCONScore.append(reqTime)

    # How many web/database servers
    cat = 'Criticality of Servers-Score'
    val = 1.0 #### how many web/database server
    
    crit_no = gotPicked(df_VULCON, strategy, cat, val)
    criticalServers7.append(crit_no)
    cum_crit_no += crit_no
    per_crit = cum_crit_no/total_webdataservers_no
    percent_criticalServers7.append(per_crit)

    # how many tier 0,1,3,4 
    cat = 'High-Value Asset Identification-Score'
    val = 1.0 #### how many tier0 
    tier0_no = gotPicked(df_VULCON, strategy, cat, val)
    tier0_7.append( tier0_no )
    cum_tier0_no += tier0_no
    per_tier0 = cum_tier0_no / total_highvalueasset_no
    percent_tier0_7.append(per_tier0)
    val = 0.75 #### how many tier1
    tier1_7.append( gotPicked(df_VULCON, strategy, cat, val) )
    val = 0.5 #### how many tier3 
    tier3_7.append( gotPicked(df_VULCON, strategy, cat, val) )
    val = 0.25 #### how many tier4 
    tier4_7.append( gotPicked(df_VULCON, strategy, cat, val) )
    
    # how many critical, medium, low
    
    cat = 'CVSS Normalized-Score'
    #### how many low risk hosts
    valLo = 1
    valHi = 3.9
    
    lowRiskHosts7.append( gotPickedRange(df_VULCON, strategy, cat, valLo, valHi) )

    #### how many medium risk hosts
    valLo = 4
    valHi = 6.9

    medRiskHosts7.append( gotPickedRange(df_VULCON, strategy, cat, valLo, valHi) )
    
    #### how many high risk hosts
    valLo = 7
    valHi = 8.9
    
    hiRiskHosts7.append( gotPickedRange(df_VULCON, strategy, cat, valLo, valHi) )
    
    #### how many critical risk hosts
    valLo = 9
    valHi = 10

    crtiRiskHosts7.append( gotPickedRange(df_VULCON, strategy, cat, valLo, valHi) )
    
    # how many susceptible hosts
    cat = 'Susceptibility of Hosts-Score'
    
    #how many low susceptible
    val = 0.25 
    lowSusceptible7.append( gotPicked(df_VULCON, strategy, cat, val) )
    #how many medium susceptible
    val = 0.5
    medSusceptible7.append( gotPicked(df_VULCON, strategy, cat, val) )
    #how many high susceptible
    val = 1.0
    hi_sus_no = gotPicked(df_VULCON, strategy, cat, val)
    hiSusceptible7.append( hi_sus_no )
    cum_highsus_no += hi_sus_no
    per_hi_sus = cum_highsus_no / total_lowprotectionmachine_no
    
    percent_hiSusceptible7.append(per_hi_sus)    

total_tier7 = sum(tier0_7) + sum(tier1_7)


# mit_time_dict_machine1 = {}
# for m in crit_machines:
#     mit_time_dict_machine1[m] = 0

# for keys, items in crit_machines_dict.items():
#     no = 0
#     for i in mit_counter_dict1[keys]:
#         no += i
#         if no >= crit_machines_dict[keys]:
#             mit_time_dict_machine1[keys] = mit_counter_dict1[keys].index(i)
#             break


total_mit_machine1 = {}
for m in crit_machines: 
    total_mit_machine1[m] = 0
    
for keys,items in mit_counter_dict1.items():
    total_mit_machine1[keys] = sum(mit_counter_dict1[keys])
    

total_mit_machine5 = {}
for m in crit_machines: 
    total_mit_machine5[m] = 0
    
for keys,items in mit_counter_dict5.items():
    total_mit_machine5[keys] = sum(mit_counter_dict5[keys])

total_mit_machine6 = {}
for m in crit_machines: 
    total_mit_machine6[m] = 0
    
for keys,items in mit_counter_dict6.items():
    total_mit_machine6[keys] = sum(mit_counter_dict6[keys])
    
total_mit_machine7 = {}
for m in crit_machines: 
    total_mit_machine7[m] = 0
    
for keys,items in mit_counter_dict7.items():
    total_mit_machine7[keys] = sum(mit_counter_dict7[keys])
    
    

    
import csv

it_ = [str(i) for i in range(52)]
cols = ['Machines'] + it_

rows = []
for keys,items in mit_counter_dict7.items():
    t = [keys]
    for item in items:
        t.append(item)
    rows.append(t)
    
with open('Machine wise mitigation VULCON.csv', 'w') as f:

    # using csv.writer method from CSV package
    write = csv.writer(f)

    write.writerow(cols)
    write.writerows(rows)
    
cols = ['Machines','Total No Vi']
rows = []
for keys,items in crit_machines_dict.items():
    t = [keys,items]
    rows.append(t)
    
with open('Machine wise total VI.csv', 'w') as f:

    # using csv.writer method from CSV package
    write = csv.writer(f)

    write.writerow(cols)
    write.writerows(rows)
    
    


