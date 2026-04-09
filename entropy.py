import math

def shannon_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum([p * math.log2(p) for p in prob])