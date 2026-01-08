# distutils: language=c
# cython: language_level=3

"""
Cython extension for high-performance packet processing.
This module provides optimized functions for VPN packet encryption/decryption.
"""

from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.string cimport memcpy, memset
cimport cython

import os
import time
from typing import Tuple

# Import cryptography libraries for actual crypto operations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


@cython.boundscheck(False)
@cython.wraparound(False)
cdef class FastPacketProcessor:
    """High-performance packet processor using Cython."""
    
    cdef readonly object cipher
    cdef readonly bytes key
    cdef readonly bytes iv
    cdef uint64_t packet_counter
    
    def __cinit__(self, cipher_name: str, key: bytes, iv: bytes = None):
        """Initialize the fast packet processor."""
        self.packet_counter = 0
        self.key = key
        if iv is None:
            self.iv = os.urandom(16)
        else:
            self.iv = iv
        
        # Setup cipher based on name
        if cipher_name.startswith('AES'):
            key_size = int(cipher_name.split('-')[1]) // 8
            if 'GCM' in cipher_name:
                self.cipher = Cipher(
                    algorithms.AES(key[:key_size]), 
                    modes.GCM(self.iv), 
                    backend=default_backend()
                )
            else:
                self.cipher = Cipher(
                    algorithms.AES(key[:key_size]), 
                    modes.CBC(self.iv), 
                    backend=default_backend()
                )
    
    @cython.boundscheck(False)
    cpdef bytes encrypt_fast(self, bytes data):
        """Fast encryption using Cython optimizations."""
        cdef Py_ssize_t data_len = len(data)
        cdef bytes result
        
        encryptor = self.cipher.encryptor()
        result = encryptor.update(data) + encryptor.finalize()
        
        self.packet_counter += 1
        return result
    
    @cython.boundscheck(False)
    cpdef bytes decrypt_fast(self, bytes data):
        """Fast decryption using Cython optimizations."""
        cdef Py_ssize_t data_len = len(data)
        cdef bytes result
        
        decryptor = self.cipher.decryptor()
        result = decryptor.update(data) + decryptor.finalize()
        
        return result
    
    @cython.boundscheck(False)
    cpdef uint64_t get_packet_count(self):
        """Get packet counter."""
        return self.packet_counter


@cython.boundscheck(False)
@cython.wraparound(False)
cdef class MemoryPool:
    """Memory pool for efficient packet buffer management."""
    
    cdef list buffer_pool
    cdef int buffer_size
    cdef int max_buffers
    
    def __cinit__(self, int buffer_size=1500, int max_buffers=1000):
        """Initialize memory pool."""
        self.buffer_size = buffer_size
        self.max_buffers = max_buffers
        self.buffer_pool = []
        
        # Pre-allocate buffers
        cdef int i
        for i in range(max_buffers):
            self.buffer_pool.append(bytearray(buffer_size))
    
    @cython.boundscheck(False)
    cpdef bytes get_buffer(self):
        """Get a buffer from the pool."""
        if self.buffer_pool:
            return bytes(self.buffer_pool.pop())
        else:
            return bytearray(self.buffer_size)
    
    @cython.boundscheck(False)
    cpdef void return_buffer(self, bytes buffer):
        """Return a buffer to the pool."""
        if len(self.buffer_pool) < self.max_buffers:
            self.buffer_pool.append(bytearray(buffer))


@cython.boundscheck(False)
@cython.wraparound(False)
cdef class PacketChecksum:
    """Fast checksum calculation for packets."""
    
    @staticmethod
    cdef uint32_t crc32_fast(const uint8_t* data, size_t length):
        """Fast CRC32 calculation."""
        cdef uint32_t crc = 0xFFFFFFFF
        cdef size_t i
        cdef uint32_t byte_val
        
        for i in range(length):
            byte_val = data[i]
            crc ^= byte_val
            cdef int j
            for j in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
        
        return crc ^ 0xFFFFFFFF
    
    @staticmethod
    cpdef uint32_t calculate_checksum(bytes data):
        """Calculate packet checksum."""
        cdef const uint8_t* data_ptr = data
        cdef size_t length = len(data)
        return PacketChecksum.crc32_fast(data_ptr, length)


# Performance optimization functions
@cython.boundscheck(False)
cpdef bytes xor_bytes_fast(bytes a, bytes b):
    """Fast XOR operation for two byte arrays."""
    cdef Py_ssize_t length = min(len(a), len(b))
    cdef bytes result = bytearray(length)
    cdef Py_ssize_t i
    
    for i in range(length):
        result[i] = a[i] ^ b[i]
    
    return bytes(result)


@cython.boundscheck(False)
cpdef bytes pad_packet_fast(bytes data, int block_size):
    """Fast PKCS#7 padding."""
    cdef Py_ssize_t data_len = len(data)
    cdef int pad_length = block_size - (data_len % block_size)
    cdef bytes result = bytearray(data_len + pad_length)
    
    # Copy original data
    cdef Py_ssize_t i
    for i in range(data_len):
        result[i] = data[i]
    
    # Add padding
    for i in range(pad_length):
        result[data_len + i] = pad_length
    
    return bytes(result)


@cython.boundscheck(False)
cpdef bytes unpad_packet_fast(bytes data):
    """Fast PKCS#7 unpadding."""
    cdef Py_ssize_t data_len = len(data)
    if data_len == 0:
        return data
    
    cdef int pad_length = data[data_len - 1]
    if pad_length > data_len or pad_length == 0:
        return data
    
    return data[:data_len - pad_length]
