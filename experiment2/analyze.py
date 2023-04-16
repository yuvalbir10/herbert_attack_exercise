
import matplotlib.pyplot as plt
x=[]
y=[]

with open("offsetscanres.txt", 'r') as file:
    text = file.readlines()
    for index, val in enumerate(text):
        x.append(index)
        y.append(int(val.split(':')[-1].replace('\n','')))
plt.plot(x,y)
plt.title("Offset Scanning Experiment\nHighest Latency out of 4k attempts")
plt.xlabel("Offset[decimal]")
plt.ylabel("#Highest Latency")
plt.savefig("lala")
print(x)
print(y)

