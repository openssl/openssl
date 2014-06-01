primes = [2, 3, 5, 7, 11, 13]

safe_prefix = 'safe_'

for safe in (False, True):
    muliplier = 1 if not safe else 2
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

    print('static const int %sprime_offsets[%d] = {' % (
        safe_prefix if safe else '', len(offsets)))
    print_buffer = '\t'
    for offset in offsets:
        if len(print_buffer) > 60:
            print(print_buffer[:-1])
            print_buffer = '\t'
        print_buffer += '%d, ' % offset
    print(print_buffer[:-2] + ' };')
    print('static const int %sprime_offset_count = %d;' % (
        safe_prefix if safe else '', len(offsets)))
    print('static const int %sprime_multiplier = %d;' % (
        safe_prefix if safe else '', muliplier))
    print('static const int %sprime_multiplier_bits = %d;' % (
        safe_prefix if safe else '', muliplier.bit_length()))

    print('')

print('static const int first_prime_index = %d;' % len(primes))
