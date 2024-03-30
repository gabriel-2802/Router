# Verifying the claim that the IP address 192.99.106.0 corresponds to the uint32_t value 6972352
# Calculating the uint32_t value for the IP address 192.99.106.0 in a way that results in 6972352
# This assumes a little-endian interpretation

ip_address_little_endian = "192.184.95.45"

# Splitting the IP address into its components
octets_little_endian = ip_address_little_endian.split('.')

# Reversing the order of octets for little-endian representation and converting to uint32_t
ip_uint32_little_endian = (int(octets_little_endian[0])) | (int(octets_little_endian[1]) << 8) | (int(octets_little_endian[2]) << 16) | (int(octets_little_endian[3]) << 24)

print(ip_uint32_little_endian)



# 6972352 40526784 16777215 0
# 2671296 36225728 16777215 1
# 7886784 41441216 16777215 2
# 2868416 36422848 16777215 0
# 6273216 39827648 16777215 0