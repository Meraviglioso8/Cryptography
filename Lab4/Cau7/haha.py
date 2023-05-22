array = b"maduiersnfotvbyl"
v3="flyers"
p5=""

for i in range(6):
    for c in range (100,123):
        if(array[c&0xF] ==ord(v3[i])):
            p5+=chr(c)
            break

print (p5)