
# coding: utf-8

# In[ ]:

import sage.all
from sage.crypto.mq.rijndael_gf import *
import itertools
from sage.misc.mrange import cantor_product

def hamming_circle(s, n, alphabet):
    """Generate strings over alphabet whose Hamming distance from s is
    exactly n.

    >>> sorted(hamming_circle('abc', 0, 'abc'))
    ['abc']
    >>> sorted(hamming_circle('abc', 1, 'abc'))
    ['aac', 'aba', 'abb', 'acc', 'bbc', 'cbc']
    >>> sorted(hamming_circle('aaa', 2, 'ab'))
    ['abb', 'bab', 'bba']

    """
    #from https://codereview.stackexchange.com/questions/88912
    #     /create-a-list-of-all-strings-within-hamming-distance-of-a-reference-string-with
    for positions in itertools.combinations(range(len(s)), n):
        for replacements in itertools.product(range(len(alphabet) - 1), repeat=n):
            cousin = list(s)
            for p, r in zip(positions, replacements):
                if cousin[p] == alphabet[r]:
                    cousin[p] = alphabet[-1]
                else:
                    cousin[p] = alphabet[r]
            yield ''.join(cousin)

def hamming_ball(s, n, alphabet):
    """Generate strings over alphabet whose Hamming distance from s is
    less than or equal to n.

    >>> sorted(hamming_ball('abc', 0, 'abc'))
    ['abc']
    >>> sorted(hamming_ball('abc', 1, 'abc'))
    ['aac', 'aba', 'abb', 'abc', 'acc', 'bbc', 'cbc']
    >>> sorted(hamming_ball('aaa', 2, 'ab'))
    ['aaa', 'aab', 'aba', 'abb', 'baa', 'bab', 'bba']

    """
    return itertools.chain.from_iterable(hamming_circle(s, i, alphabet)
                               for i in range(n + 1))


def likelihood(guess, choice, d0, d1):
    """Kalkuliert Wahrscheinlichkeit, dass Bitstring 'guess' zu 'choice' geflippt ist"""
    wert=1
    assert len(guess)==len(choice)
    for i in range(len(guess)):
        if guess[i]==choice[i] and guess[i]=='0':
            wert*=(1-d1)
        elif guess[i]==choice[i] and guess[i]=='1':
            wert*=(1-d0)
        elif guess[i]!=choice[i] and guess[i]=='0':
            wert*=d1
        elif guess[i]!=choice[i] and guess[i]=='1':
            wert*=d0
    return wert


def core(set_bytes,first_byte):
    """Berechnet die entsprechenden 3 Byte des ersten Rundenschlüssels von AES bei gegebenen 4 Byte"""
    assert len(set_bytes)==32
    sbox= [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
     0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
     0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
     0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
     0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
     0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
     0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
     0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
     0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
     0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
     0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
     0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
     0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
     0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
     0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
     0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    h1=int(set_bytes[24:],2)
    h=sbox[h1]
    #Das erste Byte ist als einziges vom Rcon betroffen
    if first_byte==1:
        h=h^^1
    add_byte1=int(set_bytes[:8],2)^^h
    add_byte2=int(set_bytes[8:16],2)^^add_byte1
    add_byte3=int(set_bytes[16:24],2)^^add_byte2
    ausgabe=set_bytes+'{0:08b}'.format(add_byte1)+'{0:08b}'.format(add_byte2)+'{0:08b}'.format(add_byte3)
    return ausgabe

@parallel(1)
def create_list(num, sample, sample_full, first_byte, d0, d1, dist, cut):
    """Erstellt eine Liste aller Bitstrings mit max. Distanz von 'dist' zum gegebenen 
    Bitstring 'sample'(mit min. 'Flip'-Wahrscheinlichkeit von 'cut')"""
    ham=[item for item in hamming_ball(sample, dist, '01')]
    l=[]
    for item in ham:
        prop=likelihood(core(item,first_byte),sample_full,d0,d1)
        if prop>=cut:
            l.append((item, prop))
    return l



def recon_aes_128(master_key, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, 
                  d0, d1, cut_1, cut_2, cut_3, test, dist=3, breakpoint=15):
    """Rekonstruiert einen AES-Schlüssel aus gegebenen Schlüssel+Rundenschlüssel.
    'dist' beschreibt die max. Hammingdistanz der einzelnen Schlüsselteile,
    'cut_1' - 'cut_3' sind Wahrscheinlichkeitsgrenzen,
    'test' ist der korrekte AES-Schlüssel zum gegentesten,
    'breakpoint' gibt die 'Suchtiefe', bzw. Anzahl der max. Kombinationen (als maximaler Index) an
    """
    rgf = RijndaelGF(4, 4)
    t=cputime()
    w=walltime()
    
    if (len(master_key)==32 and len(master_key)==len(key1) and len(key1)==len(key2) and 
        len(key1)==len(key3) and len(key1)==len(key4) and len(key1)==len(key5) and 
        len(key1)==len(key6) and len(key1)==len(key7) and len(key1)==len(key8) and 
        len(key1)==len(key9) and len(key1)==len(key10)):
        key_state_mk = rgf._hex_to_GF(master_key)
        key_state_k1 = rgf._hex_to_GF(key1)
        key_state_k2 = rgf._hex_to_GF(key2)
        key_state_k3 = rgf._hex_to_GF(key3)
        key_state_k4 = rgf._hex_to_GF(key4)
        key_state_k5 = rgf._hex_to_GF(key5)
        key_state_k6 = rgf._hex_to_GF(key6)
        key_state_k7 = rgf._hex_to_GF(key7)
        key_state_k8 = rgf._hex_to_GF(key8)
        key_state_k9 = rgf._hex_to_GF(key9)
        key_state_k10 = rgf._hex_to_GF(key10)
    elif (len(master_key)==128 and len(master_key)==len(key1) and len(key1)==len(key2) and 
        len(key1)==len(key3) and len(key1)==len(key4) and len(key1)==len(key5) and 
        len(key1)==len(key6) and len(key1)==len(key7) and len(key1)==len(key8) and 
        len(key1)==len(key9) and len(key1)==len(key10)):
        key_state_mk = rgf._bin_to_GF(master_key)
        key_state_k1 = rgf._bin_to_GF(key1)
        key_state_k2 = rgf._bin_to_GF(key2)
        key_state_k3 = rgf._bin_to_GF(key3)
        key_state_k4 = rgf._bin_to_GF(key4)
        key_state_k5 = rgf._bin_to_GF(key5)
        key_state_k6 = rgf._bin_to_GF(key6)
        key_state_k7 = rgf._bin_to_GF(key7)
        key_state_k8 = rgf._bin_to_GF(key8)
        key_state_k9 = rgf._bin_to_GF(key9)
        key_state_k10 = rgf._bin_to_GF(key10)
    else:
        return 'There was a mistake; please enter 11 32-byte hexadecimal strings or 11 128-bit bitstrings.'
    
    key_string=''.join([rgf._GF_to_bin(key_state_mk),
                        rgf._GF_to_bin(key_state_k1),
                        rgf._GF_to_bin(key_state_k2),
                        rgf._GF_to_bin(key_state_k3),
                        rgf._GF_to_bin(key_state_k4),
                        rgf._GF_to_bin(key_state_k5),
                        rgf._GF_to_bin(key_state_k6),
                        rgf._GF_to_bin(key_state_k7),
                        rgf._GF_to_bin(key_state_k8),
                        rgf._GF_to_bin(key_state_k9),
                        rgf._GF_to_bin(key_state_k10)])
            
    
    #Erstellung der 'slice'
    sample_1=''.join([rgf._GF_to_bin(key_state_mk[0][0]),
                      rgf._GF_to_bin(key_state_mk[0][1]),
                      rgf._GF_to_bin(key_state_mk[0][2]),
                      rgf._GF_to_bin(key_state_mk[1][3])])
    
    sample_2=''.join([rgf._GF_to_bin(key_state_mk[1][0]),
                      rgf._GF_to_bin(key_state_mk[1][1]),
                      rgf._GF_to_bin(key_state_mk[1][2]),
                      rgf._GF_to_bin(key_state_mk[2][3])])
    
    sample_3=''.join([rgf._GF_to_bin(key_state_mk[2][0]),
                      rgf._GF_to_bin(key_state_mk[2][1]),
                      rgf._GF_to_bin(key_state_mk[2][2]),
                      rgf._GF_to_bin(key_state_mk[3][3])])
    
    sample_4=''.join([rgf._GF_to_bin(key_state_mk[3][0]),
                      rgf._GF_to_bin(key_state_mk[3][1]),
                      rgf._GF_to_bin(key_state_mk[3][2]),
                      rgf._GF_to_bin(key_state_mk[0][3])])
    
    sample_1_full=''.join([sample_1,
                           rgf._GF_to_bin(key_state_k1[0][0]),
                           rgf._GF_to_bin(key_state_k1[0][1]),
                           rgf._GF_to_bin(key_state_k1[0][2])])
    
    sample_2_full=''.join([sample_2,
                           rgf._GF_to_bin(key_state_k1[1][0]),
                           rgf._GF_to_bin(key_state_k1[1][1]),
                           rgf._GF_to_bin(key_state_k1[1][2])])
    
    sample_3_full=''.join([sample_3,
                           rgf._GF_to_bin(key_state_k1[2][0]),
                           rgf._GF_to_bin(key_state_k1[2][1]),
                           rgf._GF_to_bin(key_state_k1[2][2])])
    
    sample_4_full=''.join([sample_4,
                           rgf._GF_to_bin(key_state_k1[3][0]),
                           rgf._GF_to_bin(key_state_k1[3][1]),
                           rgf._GF_to_bin(key_state_k1[3][2])])
    
            
    Samples_1=[]
    Samples_2=[]
    Samples_3=[]
    Samples_4=[]
    
    #Erstellung der Listen mit Bitstrings mit max. Hammingdistanz von 'dist'
    Sample_List=list(create_list([(1, sample_1, sample_1_full, 1, d0, d1, dist, cut_1),
                                  (2, sample_2, sample_2_full, 0, d0, d1, dist, cut_1),
                                  (3, sample_3, sample_3_full, 0, d0, d1, dist, cut_1),
                                  (4, sample_4, sample_4_full, 0, d0, d1, dist, cut_1)]))
    Sample_List.sort()
    
    Samples_1=Sample_List[0][1]
    Samples_2=Sample_List[1][1]
    Samples_3=Sample_List[2][1]
    Samples_4=Sample_List[3][1]
    
    Sample_List=[]

    #Sortierung der 4 Listen nach der Wahrscheinlichkeit der Übereinstimmung
    Samples_1.sort(key=operator.itemgetter(1), reverse=True)
    Samples_2.sort(key=operator.itemgetter(1), reverse=True)
    Samples_3.sort(key=operator.itemgetter(1), reverse=True)
    Samples_4.sort(key=operator.itemgetter(1), reverse=True)
    
    sampletime_cpu=cputime(t)
    sampletime_wall=walltime(w)
    
    counter_can=0
    counter_miss=0
    
    #Testen aller Kombinationen, beginnend mit den wahrscheinlichsten Kandidaten
    for (s1,s2,s3,s4) in cantor_product(range(len(Samples_1)),range(len(Samples_2)),
                                        range(len(Samples_3)),range(len(Samples_4))):
        if s1==breakpoint:
            return ''.join(['Leider erfolglos; ', '\n',
                            'Gesamtzeit (CPU): ',str(cputime(t)),' sek', '\n',
                            'Gesamtzeit (Wall): ',str(walltime(w)),' sek', '\n',
                            'Indizes: ',str((s1,s2,s3,s4)), '\n',
                            'Kandidaten: ', str(counter_can), '\n',
                            'Fehlschlaege: ', str(counter_miss), '\n',
                            'Sampletime CPU: ', str(sampletime_cpu), ' sek', '\n',
                            'Sampletime Wall: ', str(sampletime_wall), ' sek'])
        else:
            if (Samples_1[s1][1]*Samples_2[s2][1]*Samples_3[s3][1]*Samples_4[s4][1])>=cut_2:
                choice_list=[Samples_1[s1][0][:8],
                             Samples_2[s2][0][:8],
                             Samples_3[s3][0][:8],
                             Samples_4[s4][0][:8],
                             Samples_1[s1][0][8:16],
                             Samples_2[s2][0][8:16],
                             Samples_3[s3][0][8:16],
                             Samples_4[s4][0][8:16],
                             Samples_1[s1][0][16:24],
                             Samples_2[s2][0][16:24],
                             Samples_3[s3][0][16:24],
                             Samples_4[s4][0][16:24],
                             Samples_4[s4][0][24:],
                             Samples_1[s1][0][24:],
                             Samples_2[s2][0][24:],
                             Samples_3[s3][0][24:]]
                choice=''.join(choice_list)
                l=[rgf._GF_to_bin(x) for x in rgf.expand_key(rgf._bin_to_GF(choice))]
                hl=''.join(l)
                if likelihood(hl, key_string, d0, d1)>=cut_3:
                    counter_can+=1
                    #Statt Vergleich könnte hier eine Ausgabe des Kandidaten erstellt werden
                    if int(choice,2)==int(test,16):
                        return ('Erfolg bei Kandidat '+ str(counter_can) + '; ' + '\n' + 
                                '# Kombinationen unter cut_3: ' +str(counter_miss) + '; ' + '\n' +
                                'Indizes: ' + str((s1,s2,s3,s4)) + '; ' + '\n' +
                                'Sampletime CPU: ' + str(sampletime_cpu) + ' sek; ' + '\n' +
                                'Sampletime Wall: ' + str(sampletime_wall) +' sek; ' + '\n' +
                                'Gesamtzeit (CPU): ' + str(cputime(t)) + ' sek; ' + '\n' +
                                'Gesamtzeit (Wall): ' + str(walltime(w)) + ' sek')
                else:
                    counter_miss+=1

