"""Remove only the experimental Zygote kernel-stdio options."""
def remove_kernel_stdio(data):
    option=b'    stdio_to_kmsg\n'
    if data.count(option)!=1:
        raise ValueError('Expected exactly one experimental stdio option')
    return data.replace(option,b'',1)
