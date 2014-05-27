primes = [2, 3, 5, 7]
safe = True

muliplier = 1
for p in primes:
    muliplier *= p

offsets = []
for x in range(3, muliplier + 3, 2):
    prime = True
    for p in primes:
        if not x % p or (safe and not ((x - 1) / 2) % p):
            prime = False
            break

    if prime:
        offsets.append(x)

print(offsets)
print(len(offsets))
print(muliplier)
