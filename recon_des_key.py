
# coding: utf-8

# In[ ]:

def recon_des_key((key1,key2,key3,key4,key5,key6,key7,key8,key9,key10,key11,key12,key13,key14,key15,key16),d0,d1):
    
    """Reconstructs a DES-key from given roundkeys and known errorpropabilities (d0: propability 1 flipped to 0;
    d1: propability 0 flipped to 1)
    """
    r=1/2
    if d0 not in [0,1] and d1 not in [0,1] and d0!=d1:
        r=(log(1-d0,2)-log(d1,2))/(log(1-d0,2)+log(1-d1,2)-log(d0,2)-log(d1,2))
        
    #Zuordnung der Rundenschlüssel-Bits zum zugehörigen Masterkey-Bit    
    hk=[[key1[19],key2[9],key3[15],key4[23],key5[7],key6[16],key7[3],key9[10],
         key10[13],key11[1],key12[8],key13[22],key14[2],key16[17]],
        [key1[8],key2[0],key3[14],key4[11],key5[17],key6[9],key7[15],key8[23],key9[4],
         key10[20],key12[12],key13[10],key14[13],key15[1],key16[18]],
        [key1[12],key3[21],key5[18],key6[0],key7[14],key8[11],
         key10[19],key11[5],key12[6],key13[4],key14[20],key16[3]],
        [key1[29],key3[25],key4[44],key5[35],key6[42],key7[36],key8[43],key9[24],
         key10[38],key11[27],key13[34],key14[26],key15[46],key16[39]],
        [key1[32],key2[44],key3[35],key4[42],key5[36],key6[43],key7[31],key9[27],
         key11[34],key12[26],key13[46],key14[29],key15[41],key16[25]],
        [key2[43],key3[31],key5[45],key6[40],key7[47],key8[30],key9[46],
         key10[29],key11[41],key12[32],key13[37],key14[28],key15[33],key16[36]],
        [key2[40],key3[47],key4[30],key5[39],key7[25],key8[44],key9[37],
         key10[28],key11[33],key13[24],key14[38],key15[27],key16[45]],
        [key1[9],key2[5],key3[6],key4[4],key5[20],key7[12],key8[10],key9[21],
         key11[18],key12[0],key13[14],key14[11],key15[17],key16[19]],
        [key1[0],key2[22],key3[2],key5[19],key6[5],key7[6],key8[4],key9[7],
         key10[16],key11[3],key13[21],key15[18],key16[8]],
        [key2[10],key3[13],key4[1],key5[8],key6[22],key7[2],key9[17],
         key10[9],key11[15],key12[23],key13[7],key14[16],key15[3],key16[12]],
        [key2[41],key3[32],key4[37],key5[28],key6[33],key8[24],key9[31],
         key11[45],key12[40],key13[47],key14[30],key15[39],key16[29]],
        [key1[44],key2[37],key3[28],key4[33],key6[24],key7[38],key8[27],key9[45],
         key10[40],key11[47],key12[30],key13[39],key15[25],key16[32]],
        [key1[43],key2[24],key3[38],key4[27],key6[34],key7[26],key8[46],key9[39],
         key11[25],key12[44],key13[35],key14[42],key15[36]],
        [key1[40],key2[34],key3[26],key4[46],key5[29],key6[41],key7[32],key8[37],key9[35],
         key10[42],key11[36],key12[43],key13[31],key15[45]],
        [key1[5],key2[15],key3[23],key4[7],key5[16],key6[3],key8[21],key9[13],
         key10[1],key11[8],key12[22],key13[2],key15[19],key16[9]],
        [key1[22],key2[14],key3[11],key4[17],key5[9],key6[15],key7[23],key8[7],key9[20],
         key11[12],key12[10],key13[13],key14[1],key15[8],key16[0]],
        [key1[10],key2[21],key4[18],key5[0],key6[14],key7[11],key8[17],key9[19],key10[5],
         key11[6],key12[4],key13[20],key15[12]],
        [key1[41],key2[25],key3[44],key4[35],key5[42],key6[36],key7[43],key8[31],key9[38],
         key10[27],key12[34],key13[26],key14[46],key15[29]],
        [key1[37],key2[35],key3[42],key4[36],key5[43],key6[31],key8[45],
         key10[34],key11[26],key12[46],key13[29],key14[41],key15[32],key16[44]],
        [key1[24],key2[31],key4[45],key5[40],key6[47],key7[30],key8[39],key9[29],
         key10[41],key11[32],key12[37],key13[28],key14[33],key16[43]],
        [key1[34],key2[47],key3[30],key4[39],key6[25],key7[44],key8[35],key9[28],
         key10[33],key12[24],key13[38],key14[27],key16[40]],
        [key1[15],key2[6],key3[4],key4[20],key6[12],key7[10],key8[13],
         key10[18],key11[0],key12[14],key13[11],key14[17],key15[9],key16[5]],
        [key1[14],key2[2],key4[19],key5[5],key6[6],key7[4],key8[20],key9[16],
         key10[3],key12[21],key14[18],key15[0],key16[22]],
        [key1[21],key2[13],key3[1],key4[8],key5[22],key6[2],key8[19],key9[9],
         key10[15],key11[23],key12[7],key13[16],key14[3],key16[10]],
        [key1[25],key2[32],key3[37],key4[28],key5[33],key7[24],key8[38],
         key10[45],key11[40],key12[47],key13[30],key14[39],key16[41]],
        [key1[35],key2[28],key3[33],key5[24],key6[38],key7[27],key9[40],
         key10[47],key11[30],key12[39],key14[25],key15[44],key16[37]],
        [key1[31],key2[38],key3[27],key5[34],key6[26],key7[46],key8[29],
         key10[25],key11[44],key12[35],key13[42],key14[36],key15[43],key16[24]],
        [key1[47],key2[26],key3[46],key4[29],key5[41],key6[32],key7[37],key8[28],key9[42],
         key10[36],key11[43],key12[31],key14[45],key15[40],key16[34]],
        [key1[6],key2[23],key3[7],key4[16],key5[3],key7[21],key9[1],
         key10[8],key11[22],key12[2],key14[16],key15[5],key16[15]],
        [key1[2],key2[11],key3[17],key4[9],key5[15],key6[23],key7[7],key8[16],
         key10[12],key11[10],key12[13],key13[1],key14[8],key15[22],key16[14]],
        [key1[13],key3[18],key4[0],key5[14],key6[11],key7[17],key8[9],key9[5],
         key10[6],key11[4],key12[20],key14[12],key15[10],key16[21]],
        [key1[20],key2[16],key3[3],key5[21],key7[18],key8[0],key9[22],
         key10[2],key12[19],key13[5],key14[6],key15[4],key16[7]],
        [key1[28],key2[42],key3[36],key4[43],key5[31],key7[45],key8[40],key9[34],
         key10[26],key11[46],key12[29],key13[41],key14[32],key15[37],key16[35]],
        [key1[38],key3[45],key4[40],key5[47],key6[30],key7[39],key9[41],
         key10[32],key11[37],key12[28],key13[33],key15[24],key16[31]],
        [key1[26],key2[30],key3[39],key5[25],key6[44],key7[35],key8[42],key9[33],
         key11[24],key12[38],key13[27],key15[34],key16[47]],
        [key1[23],key2[4],key3[20],key5[12],key6[10],key7[13],key8[1],key9[18],
         key10[0],key11[14],key12[11],key13[17],key14[9],key15[15],key16[6]],
        [key1[11],key3[19],key4[5],key5[6],key6[4],key7[20],key9[3],
         key11[21],key13[18],key14[0],key15[14],key16[2]],
        [key2[1],key3[8],key4[22],key5[2],key7[19],key8[5],key9[15],
         key10[23],key11[7],key12[16],key13[3],key15[21],key16[13]],
        [key1[16],key3[12],key4[10],key5[13],key6[1],key7[8],key8[22],key9[14],
         key10[11],key11[17],key12[9],key13[15],key14[23],key15[7],key16[20]],
        [key1[42],key2[33],key4[24],key5[38],key6[27],key8[34],key9[47],
         key10[30],key11[39],key13[25],key14[44],key15[35],key16[28]],
        [key2[27],key4[34],key5[26],key6[46],key7[29],key8[41],key9[25],
         key10[44],key11[35],key12[42],key13[36],key14[43],key15[31],key16[38]],
        [key1[30],key2[46],key3[29],key4[41],key5[32],key6[37],key7[28],key8[33],key9[36],
         key10[43],key11[31],key13[45],key14[40],key15[47],key16[26]],
        [key1[4],key2[7],key3[16],key4[3],key6[21],key8[18],key9[8],
         key10[22],key11[2],key13[19],key14[5],key15[6],key16[23]],
        [key2[17],key3[9],key4[15],key5[23],key6[7],key7[16],key8[3],key9[12],
         key10[10],key11[13],key12[1],key13[8],key14[22],key15[2],key16[11]],
        [key1[1],key2[18],key3[0],key4[14],key5[11],key6[17],key7[9],key8[15],key9[6],
         key10[4],key11[20],key13[12],key14[10],key15[13]],
        [key2[3],key4[21],key6[18],key7[0],key8[14],key9[2],
         key11[19],key12[5],key13[6],key14[4],key15[20],key16[16]],
        [key1[33],key2[36],key3[43],key4[31],key6[45],key7[40],key8[47],key9[26],
         key10[46],key11[29],key12[41],key13[32],key14[37],key15[28],key16[42]],
        [key1[27],key2[45],key3[40],key4[47],key5[30],key6[39],key8[25],key9[32],
         key10[37],key11[28],key12[33],key14[24],key15[38]],
        [key1[46],key2[39],key4[25],key5[44],key6[35],key7[42],key8[36],
         key10[24],key11[38],key12[27],key14[34],key15[26],key16[30]],
        [key1[7],key2[20],key4[12],key5[10],key6[13],key7[1],key8[8],key9[0],
         key10[14],key11[11],key12[17],key13[9],key14[15],key15[23],key16[4]],
        [key1[17],key2[19],key3[5],key4[6],key5[4],key6[20],key8[12],
         key10[21],key12[18],key13[0],key14[14],key15[11]],
        [key1[18],key2[8],key3[22],key4[2],key6[19],key7[5],key8[6],key9[23],
         key10[7],key11[16],key12[3],key14[21],key16[1]],
        [key1[3],key2[12],key3[10],key4[13],key5[1],key6[8],key7[22],key8[2],key9[11],
         key10[17],key11[9],key12[15],key13[23],key14[7],key15[16]],
        [key1[36],key3[24],key4[38],key5[27],key7[34],key8[26],key9[30],
         key10[39],key12[25],key13[44],key14[35],key15[42],key16[33]],
        [key1[45],key3[34],key4[26],key5[46],key6[29],key7[41],key8[32],key9[44],
         key10[35],key11[42],key12[36],key13[43],key14[31],key16[27]],
        [key1[39],key2[29],key3[41],key4[32],key5[37],key6[28],key7[33],key9[43],
         key10[31],key12[45],key13[40],key14[47],key15[30],key16[46]]]
    
    #Erstellung des Masterkey
    k1=zero_vector(GF(2),64)
    for i in range (7):
        crt=0
        for j in range (len(hk[i])):
            if hk[i][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i]))):
            k1[i]=1
            
    for i in range (8,15):
        crt=0
        for j in range (len(hk[i-1])):
            if hk[i-1][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i-1]))):
            k1[i]=1
            
    for i in range (16,23):
        crt=0
        for j in range (len(hk[i-2])):
            if hk[i-2][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i-2]))):
            k1[i]=1
            
    for i in range (24,31):
        crt=0
        for j in range (len(hk[i-3])):
            if hk[i-3][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i-3]))):
            k1[i]=1
            
    for i in range (32,39):
        crt=0
        for j in range (len(hk[i-4])):
            if hk[i-4][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i-4]))):
            k1[i]=1
            
    for i in range (40,47):
        crt=0
        for j in range (len(hk[i-5])):
            if hk[i-5][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i-5]))):
            k1[i]=1
            
    for i in range (48,55):
        crt=0
        for j in range (len(hk[i-6])):
            if hk[i-6][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i-6]))):
            k1[i]=1
            
    for i in range (56,63):
        crt=0
        for j in range (len(hk[i-7])):
            if hk[i-7][j]==1:
                crt+=1
        if crt>(floor((1-r)*len(hk[i-7]))):
            k1[i]=1
            
    for m in [7,15,23,31,39,47,55,63]:
        k1[m]=(k1[m-1]+k1[m-2]+k1[m-3]+k1[m-4]+k1[m-5]+k1[m-6]+k1[m-7])
    
    k=''.join(map(str, k1))
    
    return k

