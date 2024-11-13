void burn(void* mem, size_t size) {
    if (mem != nullptr && size > 0) {
        volatile char* burnm = (volatile char*)mem;
        while (size--) {
            *burnm++ = 0;
        }
    }
}