import subprocess
import sys

def main():
    samples = 5
    allvalues = []
    allvalues_opt = []
    files = ["timing/lowmc-inst-256-256-d=1.3_short.txt", "timing/lowmc-inst-512-512-512_short.txt", "timing/lowmc-inst-128-128-128_short.txt", "timing/pq-lowmc-inst-384-384-384_short.txt"]
    if len(sys.argv) > 1 and int(sys.argv[1]) <= 3:
        file = files[int(sys.argv[1])]
    print("checking file", file)
    file = open(file, "r")
    for line in file: 
        parameters = [n for n in line.split()]
        print('./mpc_lowmc', parameters[1], parameters[3], parameters[5], parameters[3], '1')
        for i in range(samples):
            binary = './mpc_lowmc_without_opt_' + sys.argv[2]
            output = subprocess.check_output([binary, parameters[1], parameters[3], parameters[5], parameters[3], '1'], universal_newlines=True)
            output= [x for x in output.split(',') if x.strip()]
            if(len(output) != 13):
                print("ERROR")
            output = [int(x) for x in output[3:8]]
            allvalues.append(sum(output))
            binary = './mpc_lowmc_with_opt_' + sys.argv[2]
            output = subprocess.check_output([binary, parameters[1], parameters[3], parameters[5], parameters[3], '1'], universal_newlines=True)
            output= [x for x in output.split(',') if x.strip()]
            if(len(output) != 13):
                print("ERROR")
            output = [int(x) for x in output[3:8]]
            allvalues_opt.append(sum(output))
        allvalues = sorted(allvalues)
        allvalues_opt = sorted(allvalues_opt)
        mean = int(sum(allvalues[0:samples - 2]) / samples - 2)
        mean_opt = int(sum(allvalues_opt[0:samples - 2]) / samples - 2)
        print("mean:", mean , "vs" , mean_opt, "->", int((1 - (mean_opt / mean)) * 100), "% performance gain")
        allvalues = []
        allvalues_opt = []

if __name__ == "__main__":
    main()
